from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json_bytes(obj))


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def ensure_ed25519_keypair(private_key_path: Path, public_key_path: Path) -> tuple[bytes, bytes]:
    if private_key_path.exists() and public_key_path.exists():
        return private_key_path.read_bytes(), public_key_path.read_bytes()

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_path.write_bytes(sk_pem)
    public_key_path.write_bytes(pk_pem)
    return sk_pem, pk_pem


def sign_payload(private_key_pem: bytes, payload: dict[str, Any]) -> str:
    sk = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(sk, Ed25519PrivateKey)
    return _b64e(sk.sign(canonical_json_bytes(payload)))


def verify_payload_signature(public_key_pem: bytes, payload: dict[str, Any], signature_b64: str) -> bool:
    pk = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(pk, Ed25519PublicKey)
    try:
        pk.verify(_b64d(signature_b64), canonical_json_bytes(payload))
        return True
    except Exception:
        return False
