"""Ed25519 key generation, serialisation, signing, and verification."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def load_private_pem(path: Path) -> Ed25519PrivateKey:
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_pem(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def save_private_pem(key: Ed25519PrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def sign(key: Ed25519PrivateKey, msg: bytes) -> bytes:
    return key.sign(msg)


def verify(pub_pem_str: str, msg: bytes, sig: bytes) -> bool:
    pub_key = load_pem_public_key(pub_pem_str.encode("utf-8"))
    if not isinstance(pub_key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(pub_key).__name__}")
    try:
        pub_key.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
