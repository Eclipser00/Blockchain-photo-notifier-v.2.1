# photo_anchor/service.py
import os, json, hashlib
from dataclasses import dataclass
from web3 import Web3
from eth_account import Account
from hexbytes import HexBytes
from typing import Optional, Dict, Any
from .crypto_sign import (
    ed25519_generate, ed25519_sign_file, ed25519_verify_file
)
from .metadata import extract_exif_only, canonical_json

# --- Excepciones de dominio más amigables ---
class DuplicateHashError(Exception):
    """El hash ya está registrado en el contrato."""
    pass

class NotOwnerError(Exception):
    """No eres el propietario actual de este hash."""
    pass

class InvalidRecipientError(Exception):
    """La dirección de destino no es válida (cero o formato incorrecto)."""
    pass


def _owner_is_zero(owner: str) -> bool:
    # owner llega como '0x...' en hex; consideramos no registrado si es 0
    try:
        return int(owner, 16) == 0
    except Exception:
        return True

DEFAULT_RPC = "http://127.0.0.1:8545"
DEFAULT_CHAIN_ID = 1337
CHUNK_SIZE = 1024 * 1024

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def load_abi(artifact_path: str):
    with open(artifact_path, "r", encoding="utf-8") as f:
        return json.load(f)["abi"]

def sha256_file_with_exif(path: str) -> str:
    """
    SHA-256( bytes_del_archivo || canonical_json(EXIF) )
    Nota: si no hay EXIF, el JSON es {}, y el hash se basa en (bytes || "{}").
    """
    h = hashlib.sha256()
    # 1) bytes del archivo (píxeles)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    # 2) EXIF canónico
    exif = extract_exif_only(path)
    h.update(canonical_json(exif).encode("utf-8"))
    return h.hexdigest()

@dataclass
class AnchorConfig:
    rpc_url: str = DEFAULT_RPC
    contract_address: str = ""          # 0x...
    abi_path: str = "build/contracts/PhotoRegistry.json"
    private_key: Optional[str] = ""   # SOLO dev (en prod: signer/keystore)
    chain_id: int = DEFAULT_CHAIN_ID
    gas: int = 200000
    gas_price_gwei: Optional[float] = None  # si tu Ganache no admite gasPrice, pon Nones
    # Algoritmo de firma off-chain por defecto (robusto y práctico):
    signing_algorithm: str = "ed25519"
    # Rutas (opcional) a los PEM del firmante/verificador
    signer_private_pem_path: Optional[str] = None
    signer_public_pem_path: Optional[str] = None

class AnchorService:
    def __init__(self, cfg: AnchorConfig):
        self.cfg = cfg
        self.w3 = Web3(Web3.HTTPProvider(cfg.rpc_url))
        if not self.w3.isConnected():
            raise RuntimeError(f"No se pudo conectar a RPC: {cfg.rpc_url}")

        # Dirección contrato (checksum)
        addr = Web3.toChecksumAddress(cfg.contract_address.strip())

        # Validar bytecode (v5: getCode)
        code = self.w3.eth.getCode(addr)
        if code in (b"", b"\x00", HexBytes("0x")):
            raise RuntimeError("La dirección NO es un contrato (sin bytecode). Usa la dirección del contrato desplegado.")

        # Cargar ABI (usa env si está definida, si no cfg.abi_path)
        abi_path = os.getenv("PHOTO_ABI_PATH", cfg.abi_path)
        with open(abi_path, "r", encoding="utf-8") as f:
            contract_json = json.load(f)
        abi = contract_json["abi"]

        self.contract = self.w3.eth.contract(address=addr, abi=abi)

        # === Firma off-chain: carga perezosa de PEM si existen ===
        self._signer_priv_pem: Optional[bytes] = None
        self._signer_pub_pem: Optional[bytes] = None
        if self.cfg.signer_private_pem_path and os.path.exists(self.cfg.signer_private_pem_path):
            self._signer_priv_pem = open(self.cfg.signer_private_pem_path, "rb").read()
        if self.cfg.signer_public_pem_path and os.path.exists(self.cfg.signer_public_pem_path):
            self._signer_pub_pem = open(self.cfg.signer_public_pem_path, "rb").read()

    def _maybe_set_gas_price(self, tx: dict):
        """
        En web3 v5, Ganache legacy suele aceptar gasPrice.
        Si tu nodo está en modo EIP-1559 y rechaza gasPrice, comenta/pon None en config.
        """
        if self.cfg.gas_price_gwei is not None:
            # En algunos proveedores esto podría fallar; si pasa, lo ignoramos.
            try:
                tx["gasPrice"] = self.w3.toWei(self.cfg.gas_price_gwei, "gwei")
            except Exception:
                # Nodo no acepta gasPrice (solo EIP-1559). Déjalo sin gasPrice.
                pass

    def anchor(self, file_path: str, use_exif: bool = True):
        if not self.cfg.private_key:
            raise RuntimeError("Falta private_key (solo dev).")

        hexd = sha256_file_with_exif(file_path) if use_exif else sha256_file(file_path)
        h32 = "0x" + hexd
        acct = Account.from_key(self.cfg.private_key)

        # --- 1) Pre-chequeo: evita mandar la tx si ya está anclado ---
        try:
            owner, _ts = self.contract.functions.claims(h32).call()
            if not _owner_is_zero(owner):
                # Lanzamos una excepción clara y corta
                raise DuplicateHashError("Hash ya registrado: esta transacción ya se ejecutó anteriormente.")
        except DuplicateHashError:
            raise
        except Exception:
            # Si falla la lectura por alguna razón, continuamos y dejamos que on-chain decida
            pass

        # --- 2) Construcción y envío de la transacción ---
        tx = self.contract.functions.anchor(h32).buildTransaction({
            "from": acct.address,
            "nonce": self.w3.eth.getTransactionCount(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id,
        })
        self._maybe_set_gas_price(tx)

        try:
            signed = acct.signTransaction(tx)
            txh = self.w3.eth.sendRawTransaction(signed.rawTransaction)
            rc = self.w3.eth.waitForTransactionReceipt(txh)
        except Exception as e:
            # Traducción de revert a mensaje humano
            msg = str(e)
            # Clientes que exponen el nombre del error personalizado (Ganache/Hardhat a veces lo hacen)
            if "AlreadyClaimed" in msg or "already claimed" in msg.lower():
                raise DuplicateHashError("Hash ya registrado: esta transacción ya se ejecutó anteriormente.") from e
            # Reverts genéricas
            if "execution reverted" in msg.lower() or "revert" in msg.lower():
                raise RuntimeError(
                    "La transacción fue revertida por el contrato (verifica si el hash ya estaba anclado).") from e
            raise

        return {
            "fileHash": h32,
            "txHash": txh.hex(),
            "block": rc.blockNumber,
            "address": acct.address,
        }

    def verify(self, file_path: str, use_exif: bool = True):
        hexd = sha256_file_with_exif(file_path) if use_exif else sha256_file(file_path)
        h32 = "0x" + hexd
        owner, ts = self.contract.functions.claims(h32).call()
        registered = int(owner, 16) != 0
        return {
            "fileHash": h32,
            "owner": owner,
            "timestamp": ts,
            "registered": registered,
        }

    # ================== OFF-CHAIN (Ed25519) ==================

    def generate_signing_keys_if_needed(self, out_priv_path: str, out_pub_path: str) -> Dict[str, str]:
        """
        Genera y persiste un par Ed25519 si aún no existen en disco/cfg.
        """
        if self._signer_priv_pem and self._signer_pub_pem:
            return {"private_pem": self.cfg.signer_private_pem_path or "",
                    "public_pem": self.cfg.signer_public_pem_path or ""}

        kp = ed25519_generate()
        os.makedirs(os.path.dirname(out_priv_path) or ".", exist_ok=True)
        with open(out_priv_path, "wb") as f:
            f.write(kp.private_pem)
        with open(out_pub_path, "wb") as f:
            f.write(kp.public_pem)

        self._signer_priv_pem = kp.private_pem
        self._signer_pub_pem = kp.public_pem
        self.cfg.signer_private_pem_path = out_priv_path
        self.cfg.signer_public_pem_path = out_pub_path
        return {"private_pem": out_priv_path, "public_pem": out_pub_path}

    def sign_file_offchain(self, file_path: str) -> Dict[str, Any]:
        """
        Firma el SHA-256 del archivo con la clave privada Ed25519 cargada.
        """
        if self.cfg.signing_algorithm != "ed25519":
            raise RuntimeError(f"Algoritmo no soportado aún: {self.cfg.signing_algorithm}")
        if not self._signer_priv_pem:
            raise RuntimeError(
                "No hay clave privada Ed25519 cargada. Genera claves o configura signer_private_pem_path.")
        return ed25519_sign_file(file_path, self._signer_priv_pem)

    def verify_file_offchain(self, file_path: str, signature_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verifica la firma Ed25519 del hash con la clave pública Ed25519 cargada.
        """
        if self.cfg.signing_algorithm != "ed25519":
            raise RuntimeError(f"Algoritmo no soportado aún: {self.cfg.signing_algorithm}")
        if not self._signer_pub_pem:
            raise RuntimeError(
                "No hay clave pública Ed25519 cargada. Genera claves o configura signer_public_pem_path.")
        return ed25519_verify_file(file_path, self._signer_pub_pem, signature_envelope)





