# Ejecutar en la consola de python...
#Confirma el chainId de Ganache:
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
print(w3.eth.chainId)

#Verifica que la private_key es de Ganache
from eth_account import Account
print(Account.from_key("0xTU_PK").address)
