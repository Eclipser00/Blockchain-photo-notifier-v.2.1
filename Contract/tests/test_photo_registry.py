import pytest
from brownie import PhotoRegistry, accounts, reverts
from eth_abi import encode

def test_anchor_stores_owner_and_timestamp(PhotoRegistry, accounts):
    owner = accounts[0]
    c = PhotoRegistry.deploy({"from": owner})

    file_hash = "0x" + ("11"*32)
    tx = c.anchor(file_hash, {"from": owner})

    claim = c.claims(file_hash)
    assert claim[0] == owner
    assert claim[1] > 0

    # evento
    e = tx.events["Anchored"]
    assert e["fileHash"] == file_hash
    assert e["owner"] == owner
    assert e["timestamp"] == claim[1]

def test_anchor_rejects_duplicates(PhotoRegistry, accounts):
    a, b = accounts[0], accounts[1]
    c = PhotoRegistry.deploy({"from": a})

    file_hash = "0x" + ("22"*32)
    c.anchor(file_hash, {"from": a})

    with pytest.raises(Exception):
        c.anchor(file_hash, {"from": b})

def test_transfer_only_owner(PhotoRegistry, accounts):
    a, b, outsider = accounts[0], accounts[1], accounts[2]
    c = PhotoRegistry.deploy({"from": a})

    file_hash = "0x" + ("33"*32)
    c.anchor(file_hash, {"from": a})

    # no-owner no puede transferir
    with pytest.raises(Exception):
        c.transferOwner(file_hash, b, {"from": outsider})

    # nuevo owner ok
    tx = c.transferOwner(file_hash, b, {"from": a})
    claim = c.claims(file_hash)
    assert claim[0] == b

    e = tx.events["Transferred"]
    assert e["fileHash"] == file_hash
    assert e["from"] == a
    assert e["to"] == b

def test_transfer_to_zero_reverts(PhotoRegistry, accounts):
    a = accounts[0]
    c = PhotoRegistry.deploy({"from": a})

    file_hash = "0x" + ("44"*32)
    c.anchor(file_hash, {"from": a})

    with pytest.raises(Exception):
        c.transferOwner(file_hash, "0x0000000000000000000000000000000000000000", {"from": a})
