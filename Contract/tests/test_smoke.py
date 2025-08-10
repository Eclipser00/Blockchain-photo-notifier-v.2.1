import time
import pytest
from brownie import accounts
from hexbytes import HexBytes

@pytest.fixture(scope="module")
def c(PhotoRegistry, accounts):
    return PhotoRegistry.deploy({"from": accounts[0]})

def test_bulk_anchors_and_transfers(c):
    """Simula varias transacciones encadenadas: múltiples anchors y transfers."""
    a, b = accounts[0], accounts[1]
    # Crea 5 hashes distintos y ancla cada uno; luego transfiere a 'b'
    for i in range(5):
        h = HexBytes("0x" + f"{(0x50+i):02x}" * 32)   # 0x5050..., 0x5151..., ...
        tx1 = c.anchor(h, {"from": a})
        assert "Anchored" in tx1.events
        # Transferir a b
        tx2 = c.transferOwner(h, b, {"from": a})
        assert "Transferred" in tx2.events
        # Verificar dueño final
        owner, ts = c.claims(h)
        assert owner == b
        assert ts > 0

def test_gas_usage_and_ordering(c):
    """Ancla varios hashes y registra gas y orden (nonce/bloque) para simular tráfico."""
    a = accounts[0]
    hashes = [HexBytes("0x" + f"{(0x60+i):02x}" * 32) for i in range(3)]
    txs = []
    for h in hashes:
        tx = c.anchor(h, {"from": a})
        txs.append(tx)

    # Comprobaciones de 'simulación de transacciones': gas, bloque y orden
    gas_used = [tx.gas_used for tx in txs]
    blocks = [tx.block_number for tx in txs]
    nonces = [tx.nonce for tx in txs]

    # Deben ser números positivos y aumentar (no estrictamente estricto en bloques si hay minería distinta, pero localmente suele incrementar)
    assert all(g > 0 for g in gas_used)
    assert blocks == sorted(blocks)
    assert nonces == sorted(nonces)

def test_simple_eth_transfer_between_accounts():
    """Simula una transacción nativa de ETH entre cuentas (fuera del contrato)."""
    sender, receiver = accounts[0], accounts[1]
    before_sender = sender.balance()
    before_receiver = receiver.balance()

    # Enviar 0.1 ether
    tx = sender.transfer(receiver, "0.1 ether")

    assert tx.value == 10**17  # 0.1 ETH en wei
    assert sender.balance() <= before_sender - 10**17  # menos el gas (en ganache suele ser cero gasPrice, pero dejamos margen)
    assert receiver.balance() == before_receiver + 10**17
