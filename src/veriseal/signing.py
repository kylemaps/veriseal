"""Ed25519 key generation, serialisation, signing, and verification."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class KeyPassphraseError(ValueError):
    """A private key needs a passphrase that was not given, or the passphrase is wrong."""


def load_private_pem(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    try:
        key = load_pem_private_key(path.read_bytes(), password=passphrase)
    except TypeError as exc:  # cryptography's way of saying encrypted-vs-not mismatch
        if passphrase is None:
            raise KeyPassphraseError(f"{path} is encrypted; give its passphrase") from exc
        raise KeyPassphraseError(f"{path} is not encrypted, but a passphrase was given") from exc
    except ValueError as exc:
        if passphrase is not None:
            raise KeyPassphraseError(f"cannot decrypt {path}: wrong passphrase?") from exc
        raise
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_pem(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def save_private_pem(
    key: Ed25519PrivateKey,
    path: Path,
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> None:
    """Write *key* as PKCS#8 PEM, encrypted with *passphrase* if one is given.

    The file is created readable and writable by its owner only (mode 0600; on Windows
    the folder's permissions apply). An existing file is never replaced unless
    *overwrite* is set: FileExistsError instead.
    """
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    if overwrite:
        path.unlink(missing_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
        f.write(pem)


def public_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


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
