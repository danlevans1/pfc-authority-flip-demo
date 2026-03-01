import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def stable_json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_object(obj: Any) -> str:
    return sha256_hex(stable_json_dumps(obj).encode("utf-8"))


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, bytes]:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        public_key_bytes = PUBLIC_KEY_PATH.read_bytes()
        if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Expected Ed25519 key material")
        return private_key, public_key, public_key_bytes

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    return private_key, public_key, public_pem


def sign_message(private_key: Ed25519PrivateKey, message_bytes: bytes) -> bytes:
    return private_key.sign(message_bytes)


def verify_signature(public_key: Ed25519PublicKey, message_bytes: bytes, signature_bytes: bytes) -> bool:
    try:
        public_key.verify(signature_bytes, message_bytes)
        return True
    except Exception:
        return False


def compute_decision_core(policy: dict[str, Any], request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    policy_hash = hash_object(policy)
    request_hash = hash_object(request)

    requested = request["requested_exposure_usd"]
    limit = policy["max_exposure_usd"]
    enforcement = policy.get("enforcement")

    over_limit = requested > limit
    allow = not (over_limit and enforcement == "deny")

    if allow:
        event = "ALLOW"
        reason = "Requested exposure is within policy limit"
    else:
        event = "AUTHORITY_REVOKED"
        reason = "Requested exposure exceeds policy limit"

    decision_core = {
        "v": 1,
        "event": event,
        "reason": reason,
        "policy_id": policy["policy_id"],
        "policy_hash": policy_hash,
        "request_hash": request_hash,
        "requested_exposure_usd": requested,
        "authorized_limit_usd": limit,
        "action": request["action"],
        "symbol": request.get("symbol"),
        "side": request.get("side"),
    }
    return decision_core, allow


def authority_check(policy: dict[str, Any], request: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    private_key, public_key, public_key_bytes = ensure_keys()
    decision_core, allow = compute_decision_core(policy, request)
    decision_hash = hash_object(decision_core)

    # We sign the UTF-8 bytes of the deterministic decision hash string.
    signed_message = decision_hash.encode("utf-8")
    signature = sign_message(private_key, signed_message)

    decision_record = {
        "v": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "decision_core": decision_core,
        "decision_hash": decision_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signature_alg": "ed25519",
        "public_key_fingerprint": sha256_hex(public_key_bytes),
    }

    if not verify_signature(public_key, signed_message, signature):
        raise RuntimeError("Generated signature did not verify")

    return allow, decision_record
