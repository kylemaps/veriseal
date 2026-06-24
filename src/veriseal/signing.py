"""Ed25519 key generation, serialisation, signing, and verification."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def load_private_pem(path: Path) -> Ed25519PrivateKey:
    return load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]


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
    try:
        pub_key.verify(sig, msg)  # type: ignore[attr-defined]
        return True
    except InvalidSignature:
        return False
