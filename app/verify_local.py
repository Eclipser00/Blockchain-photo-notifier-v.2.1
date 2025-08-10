from web3 import Web3
import json, hashlib, os, sys

RPC = "http://127.0.0.1:8545"
CONTRACT = os.environ.get("PHOTO_REGISTRY_ADDR")

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
    h32 = "0x" + hexd

    owner, ts = reg.functions.claims(h32).call()
    registered = int(owner, 16) != 0
    print("HASH:", h32)
    print("OWNER:", owner)
    print("TS:   ", ts)
    print("OK?   ", "VERIFICADA" if registered else "NO REGISTRADA")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python verify_local.py ruta/a/tu_foto.jpg")
        sys.exit(1)
    main(sys.argv[1])
