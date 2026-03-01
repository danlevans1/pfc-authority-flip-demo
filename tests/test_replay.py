import json
import tempfile
import unittest
from pathlib import Path

from pfc_engine import authority_check, compute_decision_core, load_json
from verify_replay import verify_replay


BASE_DIR = Path(__file__).resolve().parent.parent


class ReplayTests(unittest.TestCase):
    def test_replay_passes_for_blocked_trade(self) -> None:
        policy = load_json(BASE_DIR / "policy.json")
        request = load_json(BASE_DIR / "agent_request.json")

        allow, decision_record = authority_check(policy, request)
        self.assertFalse(allow)
        self.assertEqual(decision_record["decision_core"]["event"], "AUTHORITY_REVOKED")

        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "decision_record.json"
            artifact_path.write_text(json.dumps(decision_record), encoding="utf-8")

            ok, checks = verify_replay(
                policy_path=BASE_DIR / "policy.json",
                request_path=BASE_DIR / "agent_request.json",
                artifact_path=artifact_path,
                public_key_path=BASE_DIR / "keys" / "public_key.pem",
            )

        self.assertTrue(ok)
        self.assertTrue(all(flag for _, flag in checks))

    def test_allow_path_when_under_limit(self) -> None:
        policy = load_json(BASE_DIR / "policy.json")
        request = load_json(BASE_DIR / "agent_request.json")
        request["requested_exposure_usd"] = policy["max_exposure_usd"]

        allow, decision_record = authority_check(policy, request)
        self.assertTrue(allow)
        self.assertEqual(decision_record["decision_core"]["event"], "ALLOW")

        expected_core, _ = compute_decision_core(policy, request)
        self.assertEqual(decision_record["decision_core"], expected_core)

    def test_malformed_request_blocks_with_exception(self) -> None:
        policy = load_json(BASE_DIR / "policy.json")
        request = load_json(BASE_DIR / "agent_request.json")
        request.pop("action", None)

        with self.assertRaises(KeyError):
            authority_check(policy, request)

    def test_tampered_decision_record_fails_replay(self) -> None:
        policy = load_json(BASE_DIR / "policy.json")
        request = load_json(BASE_DIR / "agent_request.json")
        _, decision_record = authority_check(policy, request)
        decision_record["decision_core"]["authorized_limit_usd"] = 1

        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "decision_record.json"
            artifact_path.write_text(json.dumps(decision_record), encoding="utf-8")
            ok, checks = verify_replay(
                policy_path=BASE_DIR / "policy.json",
                request_path=BASE_DIR / "agent_request.json",
                artifact_path=artifact_path,
                public_key_path=BASE_DIR / "keys" / "public_key.pem",
            )

        failed_checks = {name for name, flag in checks if not flag}
        self.assertFalse(ok)
        self.assertTrue(
            "decision_core match" in failed_checks
            or "decision_hash match" in failed_checks
            or any(name.startswith("signature verify") for name in failed_checks)
        )


if __name__ == "__main__":
    unittest.main()
