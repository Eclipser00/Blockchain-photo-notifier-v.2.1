
from web3 import Web3
from eth_account import Account
import hashlib, json, os, pathlib

#Pseudocódigo práctico para Windows; cambia RPC_URL, CONTRACT_ADDR, ABI

# 1) Hash SHA-256 del archivo completo
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()  # hex string

w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
with open("PhotoRegistry_abi.json") as f:
    abi = json.load(f)
reg = w3.eth.contract(address="0x...CONTRACT_ADDR...", abi=abi)

def anchor_file(path, acct):
    hexd = file_sha256(path)
    h32 = w3.to_hex(hexstr=hexd)  # "0x..." de 64 hex (32 bytes)
    tx = reg.functions.anchor(h32).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "chainId": w3.eth.chain_id
    })
    tx["gas"] = w3.eth.estimate_gas(tx)
    tx["maxFeePerGas"] = w3.to_wei("25", "gwei")
    tx["maxPriorityFeePerGas"] = w3.to_wei("1.5", "gwei")
    signed = acct.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.rawTransaction)
    return hexd, txh.hex()

def verify_file(path):
    hexd = file_sha256(path)
    h32 = w3.to_hex(hexstr=hexd)
    claim = reg.functions.claims(h32).call()
    owner, ts = claim[0], claim[1]
    return {"hash": "0x"+hexd, "owner": owner, "timestamp": ts, "registered": owner != "0x0000000000000000000000000000000000000000"}
