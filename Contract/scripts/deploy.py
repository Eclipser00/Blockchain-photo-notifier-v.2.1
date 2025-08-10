from brownie import PhotoRegistry, accounts, network
import re, os

ENV_PATH = ".env"

def _set_env_var(key, value, env_path=ENV_PATH):
    # crea o reemplaza la línea KEY=...
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = []
    found = False
    for i, line in enumerate(lines):
        if line.startswith(key + "="):
            lines[i] = f"{key}={value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def main():
    acct = accounts[0]  # o accounts.add(...) si usas pk
    c = PhotoRegistry.deploy({"from": acct})
    print("Deployed:", c.address)

    # actualiza .env
    _set_env_var("PHOTO_REGISTRY_ADDR", c.address)
    # si apuntas a Ganache GUI, también fija:
    _set_env_var("PHOTO_RPC", "http://127.0.0.1:8545")  # ajusta si usas otro puerto
    # opcional: guarda chainId detectado
    _set_env_var("PHOTO_CHAIN_ID", str(network.chain.id))



# OJO CAMBIAR PUERTO EN GANACHE 8454
# cd Contract
# brownie run scripts/deploy.py ( asi iniciarenmos la blockchain)