from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pfc_scale.config import (
    GATE_PRIVATE_KEY,
    GATE_PUBLIC_KEY,
    WORKER_DECISION_PRIVATE_KEY,
    WORKER_DECISION_PUBLIC_KEY,
    WORKER_RECEIPT_PRIVATE_KEY,
    WORKER_RECEIPT_PUBLIC_KEY,
)
from pfc_scale.crypto import ensure_ed25519_keypair, hash_obj, sign_payload


class ReplayDuplicateAckTests(unittest.TestCase):
    def test_replay_checker_accepts_duplicate_ack(self) -> None:
        ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)
        ensure_ed25519_keypair(WORKER_DECISION_PRIVATE_KEY, WORKER_DECISION_PUBLIC_KEY)
        worker_receipt_sk, _ = ensure_ed25519_keypair(WORKER_RECEIPT_PRIVATE_KEY, WORKER_RECEIPT_PUBLIC_KEY)
        gate_sk, _ = ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)

        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        intent_id = str(uuid.uuid4())

        decision_payload = {
            "decision_id": str(uuid.uuid4()),
            "run_id": "test-run",
            "intent_id": intent_id,
            "allow": True,
            "reason": "ALLOW",
            "command": "echo",
            "args": ["hi"],
            "irreversible": False,
            "issued_at": now.isoformat(),
            "expires_at": exp.isoformat(),
            "commit_boundary": False,
            "source": "gate",
        }
        decision_artifact = {
            "payload": decision_payload,
            "signature": sign_payload(gate_sk, decision_payload),
            "signature_alg": "ed25519",
            "signer_kid": "gate-v1",
        }
        decision_hash = hash_obj(decision_payload)

        execution_receipt_payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": "test-run",
            "intent_id": intent_id,
            "decision_hash": decision_hash,
            "executed": True,
            "reason": "EXECUTED",
            "execution_at": now.isoformat(),
            "decision_expires_at": exp.isoformat(),
            "message_id": "1-0",
            "output": "ok",
            "finished_at": now.isoformat(),
            "receipt_kind": "execution",
            "original_intent_id": None,
            "original_receipt_hash": None,
            "original_decision_hash": None,
        }
        duplicate_receipt_payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": "test-run",
            "intent_id": intent_id,
            "decision_hash": decision_hash,
            "executed": False,
            "reason": "DUPLICATE_INTENT_ACK",
            "execution_at": now.isoformat(),
            "decision_expires_at": "",
            "message_id": "2-0",
            "output": "",
            "finished_at": now.isoformat(),
            "receipt_kind": "duplicate_ack",
            "original_intent_id": intent_id,
            "original_receipt_hash": None,
            "original_decision_hash": decision_hash,
        }

        execution_receipt = {
            "payload": execution_receipt_payload,
            "signature": sign_payload(worker_receipt_sk, execution_receipt_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }
        duplicate_receipt = {
            "payload": duplicate_receipt_payload,
            "signature": sign_payload(worker_receipt_sk, duplicate_receipt_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }

        with tempfile.TemporaryDirectory() as td:
            ledger_dir = Path(td)
            decisions_file = ledger_dir / "decisions_20260302_00.jsonl"
            receipts_file = ledger_dir / "receipts_20260302_00.jsonl"
            decisions_file.write_text(json.dumps({"decision_hash": decision_hash, "artifact": decision_artifact}) + "\n", encoding="utf-8")
            receipts_file.write_text(
                json.dumps(execution_receipt) + "\n" + json.dumps(duplicate_receipt) + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["./.venv/bin/python", "scripts/replay_check.py", "--ledger-dir", str(ledger_dir), "--sample-size", "200"],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("mismatches=0", proc.stdout)

    def test_replay_checker_run_id_filters_other_runs(self) -> None:
        ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)
        worker_receipt_sk, _ = ensure_ed25519_keypair(WORKER_RECEIPT_PRIVATE_KEY, WORKER_RECEIPT_PUBLIC_KEY)
        gate_sk, _ = ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)

        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)

        run_a = "run-a"
        run_b = "run-b"
        iid_a = str(uuid.uuid4())
        iid_b = str(uuid.uuid4())

        decision_a_payload = {
            "decision_id": str(uuid.uuid4()),
            "run_id": run_a,
            "intent_id": iid_a,
            "allow": True,
            "reason": "ALLOW",
            "command": "echo",
            "args": ["a"],
            "irreversible": False,
            "issued_at": now.isoformat(),
            "expires_at": exp.isoformat(),
            "commit_boundary": False,
            "source": "gate",
        }
        decision_b_payload = {
            "decision_id": str(uuid.uuid4()),
            "run_id": run_b,
            "intent_id": iid_b,
            "allow": True,
            "reason": "ALLOW",
            "command": "echo",
            "args": ["b"],
            "irreversible": False,
            "issued_at": now.isoformat(),
            "expires_at": exp.isoformat(),
            "commit_boundary": False,
            "source": "gate",
        }
        decision_a_hash = hash_obj(decision_a_payload)
        decision_b_hash = hash_obj(decision_b_payload)

        decision_a = {
            "decision_hash": decision_a_hash,
            "artifact": {
                "payload": decision_a_payload,
                "signature": sign_payload(gate_sk, decision_a_payload),
                "signature_alg": "ed25519",
                "signer_kid": "gate-v1",
            },
        }
        # Intentionally invalid signature for run-b to prove run-id filtering excludes it.
        decision_b = {
            "decision_hash": decision_b_hash,
            "artifact": {
                "payload": decision_b_payload,
                "signature": "AAAA",
                "signature_alg": "ed25519",
                "signer_kid": "gate-v1",
            },
        }

        receipt_a_payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": run_a,
            "intent_id": iid_a,
            "decision_hash": decision_a_hash,
            "executed": True,
            "reason": "EXECUTED",
            "execution_at": now.isoformat(),
            "decision_expires_at": exp.isoformat(),
            "message_id": "1-0",
            "output": "ok",
            "finished_at": now.isoformat(),
            "receipt_kind": "execution",
            "original_intent_id": None,
            "original_receipt_hash": None,
            "original_decision_hash": None,
        }
        receipt_b_payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": run_b,
            "intent_id": iid_b,
            "decision_hash": decision_b_hash,
            "executed": True,
            "reason": "EXECUTED",
            "execution_at": now.isoformat(),
            "decision_expires_at": exp.isoformat(),
            "message_id": "2-0",
            "output": "ok",
            "finished_at": now.isoformat(),
            "receipt_kind": "execution",
            "original_intent_id": None,
            "original_receipt_hash": None,
            "original_decision_hash": None,
        }
        receipt_a = {
            "payload": receipt_a_payload,
            "signature": sign_payload(worker_receipt_sk, receipt_a_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }
        receipt_b = {
            "payload": receipt_b_payload,
            "signature": sign_payload(worker_receipt_sk, receipt_b_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }

        with tempfile.TemporaryDirectory() as td:
            ledger_dir = Path(td)
            (ledger_dir / "decisions_20260302_00.jsonl").write_text(
                json.dumps(decision_a) + "\n" + json.dumps(decision_b) + "\n",
                encoding="utf-8",
            )
            (ledger_dir / "receipts_20260302_00.jsonl").write_text(
                json.dumps(receipt_a) + "\n" + json.dumps(receipt_b) + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["./.venv/bin/python", "scripts/replay_check.py", "--ledger-dir", str(ledger_dir), "--run-id", run_a, "--sample-size", "200"],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn(f"run_id={run_a}", proc.stdout)
            self.assertIn("decisions=1", proc.stdout)
            self.assertIn("receipts=1", proc.stdout)
            self.assertIn("mismatches=0", proc.stdout)

    def test_replay_checker_run_id_handles_mixed_field_locations(self) -> None:
        ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)
        worker_receipt_sk, _ = ensure_ed25519_keypair(WORKER_RECEIPT_PRIVATE_KEY, WORKER_RECEIPT_PUBLIC_KEY)
        gate_sk, _ = ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)

        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        run_a = "run-a-mixed"
        intent_id = str(uuid.uuid4())

        decision_payload = {
            "decision_id": str(uuid.uuid4()),
            "run_id": run_a,
            "intent_id": intent_id,
            "allow": True,
            "reason": "ALLOW",
            "command": "echo",
            "args": ["a"],
            "irreversible": False,
            "issued_at": now.isoformat(),
            "expires_at": exp.isoformat(),
            "commit_boundary": False,
            "source": "gate",
        }
        decision_hash = hash_obj(decision_payload)
        decision = {
            "decision_hash": decision_hash,
            "artifact": {
                "payload": decision_payload,
                "signature": sign_payload(gate_sk, decision_payload),
                "signature_alg": "ed25519",
                "signer_kid": "gate-v1",
            },
        }

        receipt_top_level_payload = {
            "receipt_id": str(uuid.uuid4()),
            "intent_id": intent_id,
            "decision_hash": decision_hash,
            "executed": False,
            "reason": "DENIED",
            "execution_at": now.isoformat(),
            "decision_expires_at": exp.isoformat(),
            "message_id": "1-0",
            "output": "",
            "finished_at": now.isoformat(),
            "receipt_kind": "deny",
            "original_intent_id": None,
            "original_receipt_hash": None,
            "original_decision_hash": None,
        }
        receipt_payload_level_payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": run_a,
            "intent_id": intent_id,
            "decision_hash": decision_hash,
            "executed": False,
            "reason": "DUPLICATE_INTENT_ACK",
            "execution_at": now.isoformat(),
            "decision_expires_at": "",
            "message_id": "2-0",
            "output": "",
            "finished_at": now.isoformat(),
            "receipt_kind": "duplicate_ack",
            "original_intent_id": intent_id,
            "original_receipt_hash": None,
            "original_decision_hash": decision_hash,
        }
        receipt_missing_payload = {
            "receipt_id": str(uuid.uuid4()),
            "intent_id": intent_id,
            "decision_hash": "deadbeef",
            "executed": False,
            "reason": "DENIED",
            "execution_at": now.isoformat(),
            "decision_expires_at": exp.isoformat(),
            "message_id": "3-0",
            "output": "",
            "finished_at": now.isoformat(),
            "receipt_kind": "deny",
            "original_intent_id": None,
            "original_receipt_hash": None,
            "original_decision_hash": None,
        }

        receipt_top_level = {
            "run_id": run_a,
            "payload": receipt_top_level_payload,
            "signature": sign_payload(worker_receipt_sk, receipt_top_level_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }
        receipt_payload_level = {
            "payload": receipt_payload_level_payload,
            "signature": sign_payload(worker_receipt_sk, receipt_payload_level_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }
        receipt_missing = {
            "payload": receipt_missing_payload,
            "signature": sign_payload(worker_receipt_sk, receipt_missing_payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }

        with tempfile.TemporaryDirectory() as td:
            ledger_dir = Path(td)
            (ledger_dir / "decisions_20260302_00.jsonl").write_text(json.dumps(decision) + "\n", encoding="utf-8")
            (ledger_dir / "receipts_20260302_00.jsonl").write_text(
                json.dumps(receipt_top_level) + "\n" + json.dumps(receipt_payload_level) + "\n" + json.dumps(receipt_missing) + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["./.venv/bin/python", "scripts/replay_check.py", "--ledger-dir", str(ledger_dir), "--run-id", run_a, "--sample-size", "200"],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn(f"run_id={run_a}", proc.stdout)
            self.assertIn("receipts=2", proc.stdout)
            self.assertIn("mismatches=0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
