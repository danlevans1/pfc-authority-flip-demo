import json
import sys
from pathlib import Path

try:
    from pfc_engine import authority_check, load_json
except ModuleNotFoundError as exc:
    if exc.name == "cryptography":
        print("Missing dependency: cryptography. Install with: pip install -r requirements.txt")
        raise SystemExit(1)
    raise

from verify_replay import verify_replay


BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "policy.json"
REQUEST_PATH = BASE_DIR / "agent_request.json"
ARTIFACT_PATH = BASE_DIR / "artifacts" / "decision_record.json"
ARTIFACT_DISPLAY_PATH = "artifacts/decision_record.json"


def main() -> int:
    policy = load_json(POLICY_PATH)
    request = load_json(REQUEST_PATH)

    requested = request["requested_exposure_usd"]
    limit = policy["max_exposure_usd"]

    print("=== Deterministic Authority Flip Demo ===")
    print(f"Requested exposure: ${requested:,.0f}")
    print(f"Policy max exposure: ${limit:,.0f}\n")

    try:
        allow, decision_record = authority_check(policy, request)
    except Exception as exc:
        print("STATUS: EXECUTION AUTHORITY REVOKED (ERROR)")
        print(f"REASON: Authority engine error: {type(exc).__name__}")
        print("RESULT: Trade blocked.")

        error_record = {
            "v": 1,
            "event": "AUTHORITY_REVOKED_ERROR",
            "reason": f"Authority engine error: {type(exc).__name__}",
        }
        ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with ARTIFACT_PATH.open("w", encoding="utf-8") as f:
            json.dump(error_record, f, indent=2, ensure_ascii=False)
        print(f"Artifact written: {ARTIFACT_DISPLAY_PATH}")
        return 1

    if allow:
        print("STATUS: ALLOW")
        print("REASON: Requested exposure is within policy limit")
        print("RESULT: Trade would execute (simulated).")
    else:
        reason = decision_record["decision_core"]["reason"]
        print("STATUS: EXECUTION AUTHORITY REVOKED")
        print(f"REASON: {reason}")
        print("RESULT: Trade blocked.")

    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ARTIFACT_PATH.open("w", encoding="utf-8") as f:
        json.dump(decision_record, f, indent=2, ensure_ascii=False)

    print(f"Artifact written: {ARTIFACT_DISPLAY_PATH}")

    ok, checks = verify_replay(POLICY_PATH, REQUEST_PATH, ARTIFACT_PATH, BASE_DIR / "keys" / "public_key.pem")
    print(f"\nReplay verification: {'PASS' if ok else 'FAIL'}")
    if not ok:
        for name, flag in checks:
            if not flag:
                print(f"- failed check: {name}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
