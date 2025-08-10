from web3 import Web3
from eth_account import Account
import json, hashlib, os, sys

RPC = "http://127.0.0.1:8545"
CONTRACT = os.environ.get("PHOTO_REGISTRY_ADDR")  # pon aquí tu address o usa env var
PRIV = os.environ.get("DEV_PRIVATE_KEY")          # private de Ganache (solo dev)

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main(path):
    w3 = Web3(Web3.HTTPProvider(RPC))
    with open("build/contracts/PhotoRegistry.json") as f:
        artifact = json.load(f)
    abi = artifact["abi"]

    reg = w3.eth.contract(address=CONTRACT, abi=abi)
    hexd = file_sha256(path)
    h32 = "0x" + hexd  # bytes32

    acct = Account.from_key(PRIV)
    tx = reg.functions.anchor(h32).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 200000,
        "gasPrice": w3.to_wei(1, "gwei"),
        "chainId": 1337,   # ganache -i 1337
    })
    signed = acct.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(txh)
    print("HASH:", h32)
    print("TX:  ", txh.hex())
    print("BLK: ", receipt.blockNumber)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python anchor_local.py ruta/a/tu_foto.jpg")
        sys.exit(1)
    main(sys.argv[1])
