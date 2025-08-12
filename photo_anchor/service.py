# photo_anchor/service.py
import os, json, hashlib
from dataclasses import dataclass
from typing import Optional
from web3 import Web3
from eth_account import Account
from hexbytes import HexBytes

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

@dataclass
class AnchorConfig:
    rpc_url: str = DEFAULT_RPC
    contract_address: str = ""          # 0x...
    abi_path: str = "build/contracts/PhotoRegistry.json"
    private_key: Optional[str] = None   # SOLO dev (en prod: signer/keystore)
    chain_id: int = DEFAULT_CHAIN_ID
    gas: int = 2000000000
    gas_price_gwei: Optional[float] = None  # si tu Ganache no admite gasPrice, pon None

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

    def anchor(self, file_path: str):
        if not self.cfg.private_key:
            raise RuntimeError("Falta private_key (solo dev).")
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        acct = Account.from_key(self.cfg.private_key)

        # v5: buildTransaction + getTransactionCount + chainId
        tx = self.contract.functions.anchor(h32).buildTransaction({
            "from": acct.address,
            "nonce": self.w3.eth.getTransactionCount(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id,
        })
        self._maybe_set_gas_price(tx)

        signed = acct.signTransaction(tx)
        txh = self.w3.eth.sendRawTransaction(signed.rawTransaction)
        rc = self.w3.eth.waitForTransactionReceipt(txh)

        return {
            "fileHash": h32,
            "txHash": txh.hex(),
            "block": rc.blockNumber,
            "address": acct.address,
        }

    def verify(self, file_path: str):
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        owner, ts = self.contract.functions.claims(h32).call()
        registered = int(owner, 16) != 0
        return {
            "fileHash": h32,
            "owner": owner,
            "timestamp": ts,
            "registered": registered,
        }

    def transfer_by_file(self, file_path: str, new_owner: str):
        if not self.cfg.private_key:
            raise RuntimeError("Falta private_key (solo dev).")
        if not (new_owner.startswith("0x") and len(new_owner) == 42):
            raise RuntimeError("Dirección destino inválida.")

        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        acct = Account.from_key(self.cfg.private_key)

        tx = self.contract.functions.transferOwner(h32, new_owner).buildTransaction({
            "from": acct.address,
            "nonce": self.w3.eth.getTransactionCount(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id,
        })
        self._maybe_set_gas_price(tx)

        signed = acct.signTransaction(tx)
        txh = self.w3.eth.sendRawTransaction(signed.rawTransaction)
        rc = self.w3.eth.waitForTransactionReceipt(txh)

        return {
            "fileHash": h32,
            "to": new_owner,
            "txHash": txh.hex(),
            "block": rc.blockNumber,
        }



