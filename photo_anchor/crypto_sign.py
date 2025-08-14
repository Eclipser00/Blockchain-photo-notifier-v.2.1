# photo_anchor/crypto_sign.py
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

CHUNK_SIZE = 1024 * 1024

def sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.digest()  # bytes

@dataclass
class Ed25519Keypair:
    private_pem: bytes
    public_pem: bytes

def ed25519_generate() -> Ed25519Keypair:
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return Ed25519Keypair(private_pem=priv_pem, public_pem=pub_pem)

def ed25519_load_private(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)

def ed25519_load_public(pem: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)

def ed25519_sign_file(file_path: str, private_pem: bytes) -> Dict[str, Any]:
    """
    Firma el SHA-256 del archivo (bytes) con Ed25519.
    Devuelve sobre con metadatos (algoritmo, hash hex 0x..., firma hex).
    """
    digest = sha256_file(file_path)                                # bytes
    priv = ed25519_load_private(private_pem)
    sig  = priv.sign(digest)                                       # bytes
    hexd = hashlib.sha256(open(file_path, "rb").read()).hexdigest()  # solo para 0x...
    return {
        "algorithm": "ed25519-sha256",
        "fileHash": "0x" + hexd,
        "signature": sig.hex(),   # hex string
    }

def ed25519_verify_file(file_path: str, public_pem: bytes, sig_envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verifica que la firma corresponde al SHA-256 del archivo.
    """
    expected_alg = sig_envelope.get("algorithm")
    if expected_alg not in ("ed25519-sha256", "ed25519"):
        return {"ok": False, "reason": f"Algoritmo no soportado: {expected_alg}"}

    # Comparar hash declarado vs recalculado (defensa contra sustitución de archivo)
    hexd_calc = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    file_hash_0x = "0x" + hexd_calc
    if sig_envelope.get("fileHash") != file_hash_0x:
        return {"ok": False, "reason": "El hash del archivo no coincide con el de la firma."}

    digest = sha256_file(file_path)
    sig    = bytes.fromhex(sig_envelope["signature"])
    pub    = ed25519_load_public(public_pem)
    try:
        pub.verify(sig, digest)
        return {"ok": True, "fileHash": file_hash_0x, "algorithm": expected_alg}
    except Exception as e:
        return {"ok": False, "reason": f"Firma inválida: {e}"}
