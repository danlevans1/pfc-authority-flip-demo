import argparse
import base64
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ModuleNotFoundError as exc:
    if exc.name == "cryptography":
        print("Missing dependency: cryptography. Install with: pip install -r requirements.txt")
        raise SystemExit(1)
    raise

from pfc_engine import compute_decision_core, hash_object, load_json, sha256_hex


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = BASE_DIR / "policy.json"
DEFAULT_REQUEST = BASE_DIR / "agent_request.json"
DEFAULT_ARTIFACT = BASE_DIR / "artifacts" / "decision_record.json"
DEFAULT_PUBLIC_KEY = BASE_DIR / "keys" / "public_key.pem"


def verify_replay(
    policy_path: Path = DEFAULT_POLICY,
    request_path: Path = DEFAULT_REQUEST,
    artifact_path: Path = DEFAULT_ARTIFACT,
    public_key_path: Path = DEFAULT_PUBLIC_KEY,
) -> tuple[bool, list[tuple[str, bool]]]:
    policy = load_json(policy_path)
    request = load_json(request_path)
    artifact = load_json(artifact_path)

    expected_core, _ = compute_decision_core(policy, request)

    checks: list[tuple[str, bool]] = []

    core = artifact.get("decision_core", {})
    checks.append(("policy_hash match", core.get("policy_hash") == expected_core.get("policy_hash")))
    checks.append(("request_hash match", core.get("request_hash") == expected_core.get("request_hash")))
    checks.append(("decision_core match", core == expected_core))

    expected_hash = hash_object(expected_core)
    checks.append(("decision_hash match", artifact.get("decision_hash") == expected_hash))

    public_key_bytes = public_key_path.read_bytes()
    expected_fingerprint = sha256_hex(public_key_bytes)
    checks.append(("public_key_fingerprint match", artifact.get("public_key_fingerprint") == expected_fingerprint))

    signature_b64 = artifact.get("signature", "")
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        signature = b""

    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("Public key is not Ed25519")
        public_key.verify(signature, expected_hash.encode("utf-8"))
        sig_ok = True
    except Exception:
        sig_ok = False
    checks.append(("signature verify", sig_ok))

    ok = all(flag for _, flag in checks)
    return ok, checks


def _print_results(ok: bool, checks: list[tuple[str, bool]]) -> None:
    if ok:
        print("Replay verification: PASS")
    else:
        print("Replay verification: FAIL")

    for name, flag in checks:
        print(f"- {name}: {'OK' if flag else 'FAIL'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify replayability and signature of decision record")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--request", type=Path, default=DEFAULT_REQUEST)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    args = parser.parse_args()

    try:
        ok, checks = verify_replay(args.policy, args.request, args.artifact, args.public_key)
        _print_results(ok, checks)
        return 0 if ok else 1
    except FileNotFoundError as exc:
        print(f"Replay verification: FAIL\n- missing file: {exc}")
        return 1
    except Exception as exc:
        print(f"Replay verification: FAIL\n- error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
