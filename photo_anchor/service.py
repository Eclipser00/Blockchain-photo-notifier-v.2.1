# photo_anchor/service.py
import os, json, hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any
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
    contract_address: str = ""     # 0x...
    abi_path: str = "build/contracts/PhotoRegistry.json"
    private_key: Optional[str] = None   # SOLO dev
    chain_id: int = DEFAULT_CHAIN_ID
    gas: int = 200000
    gas_price_gwei: Optional[float] = 1.0

class AnchorService:
    def __init__(self, cfg: AnchorConfig):
        self.cfg = cfg
        self.w3 = Web3(Web3.HTTPProvider(cfg.rpc_url))
        if not self.w3.isConnected():
            raise RuntimeError(f"No se pudo conectar a RPC: {cfg.rpc_url}")

        # Dirección del contrato
        addr = Web3.toChecksumAddress(cfg.contract_address.strip())

        # VALIDAR: debe haber bytecode (rechaza cuentas EOA)
        code = self.w3.eth.get_code(addr)
        if code in (b"", b"\x00", HexBytes("0x")):
            raise RuntimeError(
                "La dirección NO es un contrato (sin bytecode). Usa la dirección del contrato desplegado.")

        # Cargar ABI
        abi_path = os.getenv("PHOTO_ABI_PATH", "Contract/build/contracts/PhotoRegistry.json")
        with open(abi_path, "r") as f:
            contract_json = json.load(f)
        abi = contract_json["abi"]

        self.contract = self.w3.eth.contract(
            address=addr,
            abi=abi
        )

    def anchor(self, file_path: str):
        if not self.cfg.private_key:
            raise RuntimeError("Falta private_key (solo dev).")
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        acct = Account.from_key(self.cfg.private_key)
        tx = self.contract.functions.anchor(h32).build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id
        })
        if self.cfg.gas_price_gwei is not None:
            tx["gasPrice"] = self.w3.to_wei(self.cfg.gas_price_gwei, "gwei")
        signed = acct.sign_transaction(tx)
        txh = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        rc = self.w3.eth.wait_for_transaction_receipt(txh)
        return {"fileHash": h32, "txHash": txh.hex(), "block": rc.blockNumber, "address": acct.address}

    def verify(self, file_path: str):
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        owner, ts = self.contract.functions.claims(h32).call()
        registered = int(owner, 16) != 0
        return {"fileHash": h32, "owner": owner, "timestamp": ts, "registered": registered}

    def transfer_by_file(self, file_path: str, new_owner: str):
        if not self.cfg.private_key:
            raise RuntimeError("Falta private_key (solo dev).")
        if not (new_owner.startswith("0x") and len(new_owner) == 42):
            raise RuntimeError("Dirección destino inválida.")
        hexd = sha256_file(file_path)
        h32 = "0x" + hexd
        acct = Account.from_key(self.cfg.private_key)
        tx = self.contract.functions.transferOwner(h32, new_owner).build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "gas": self.cfg.gas,
            "chainId": self.cfg.chain_id
        })
        if self.cfg.gas_price_gwei is not None:
            tx["gasPrice"] = self.w3.to_wei(self.cfg.gas_price_gwei, "gwei")
        signed = acct.sign_transaction(tx)
        txh = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        rc = self.w3.eth.wait_for_transaction_receipt(txh)
        return {"fileHash": h32, "to": new_owner, "txHash": txh.hex(), "block": rc.blockNumber}
