from brownie import PhotoRegistry, accounts

def main():
    acct = accounts[0]        # Ganache te da 10
    c = PhotoRegistry.deploy({"from": acct})
    print("Contrato:", c.address)


# OJO CAMBIAR PUERTO EN GANACHE 8454
# cd Contract
# brownie run scripts/deploy.py ( asi iniciarenmos la blockchain)