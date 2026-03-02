from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

from pfc_scale.crypto import ensure_ed25519_keypair, sign_payload
from pfc_scale.worker import WorkerEngine


class InMemoryIndex:
    def __init__(self):
        self.seen: dict[str, str] = {}

    def has_intent(self, intent_id: str) -> bool:
        return intent_id in self.seen

    def insert_if_absent(self, intent_id: str, run_id: str, decision_hash: str, finished_at: str) -> bool:
        if intent_id in self.seen:
            return False
        self.seen[intent_id] = decision_hash
        return True

    def get_decision_hash(self, intent_id: str) -> str | None:
        return self.seen.get(intent_id)


class InMemoryLedgers:
    def __init__(self):
        self.decisions: list[dict[str, Any]] = []
        self.receipts: list[dict[str, Any]] = []

    def write_decision(self, item: dict[str, Any]) -> None:
        self.decisions.append(item)

    def write_receipt(self, item: dict[str, Any]) -> None:
        self.receipts.append(item)


class FakeExecutor:
    def __init__(self):
        self.calls = 0

    def run(self, command: str, args: list[str]) -> tuple[bool, str]:
        self.calls += 1
        return True, "ok"


class FakeGate:
    def __init__(self, gate_private_pem: bytes, responses: list[dict[str, Any]]):
        self.gate_private_pem = gate_private_pem
        self.responses = responses
        self.calls = 0

    def decide(self, intent: dict[str, Any], ttl_seconds: int | None = None, commit_boundary: bool = False) -> dict[str, Any]:
        idx = min(self.calls, len(self.responses) - 1)
        payload = dict(self.responses[idx])
        payload.setdefault("intent_id", intent.get("intent_id"))
        payload.setdefault("command", intent.get("command"))
        payload.setdefault("args", intent.get("args", []))
        payload.setdefault("irreversible", intent.get("irreversible", False))
        payload.setdefault("commit_boundary", commit_boundary)
        payload.setdefault("source", "gate")
        artifact = {
            "payload": payload,
            "signature": sign_payload(self.gate_private_pem, payload),
            "signature_alg": "ed25519",
            "signer_kid": "gate-v1",
        }
        self.calls += 1
        return artifact


class StabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.gate_priv, self.gate_pub = ensure_ed25519_keypair(root / "gate_sk.pem", root / "gate_pk.pem")
        self.worker_decision_priv, self.worker_decision_pub = ensure_ed25519_keypair(root / "wd_sk.pem", root / "wd_pk.pem")
        self.receipt_priv, self.receipt_pub = ensure_ed25519_keypair(root / "wr_sk.pem", root / "wr_pk.pem")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _engine(self, gate: FakeGate, executor: FakeExecutor | None = None) -> WorkerEngine:
        return WorkerEngine(
            run_id="test-run",
            gate_client=gate,
            index=InMemoryIndex(),
            ledgers=InMemoryLedgers(),
            executor=executor or FakeExecutor(),
            gate_public_pem=self.gate_pub,
            local_decision_private_pem=self.worker_decision_priv,
            local_decision_public_pem=self.worker_decision_pub,
            receipt_private_pem=self.receipt_priv,
        )

    def test_duplicate_intent_id_does_not_execute_twice(self) -> None:
        now = "2030-03-01T00:00:00+00:00"
        exp = "2030-03-01T01:00:00+00:00"
        gate = FakeGate(self.gate_priv, [{"decision_id": "d1", "allow": True, "reason": "ALLOW", "issued_at": now, "expires_at": exp}])
        executor = FakeExecutor()
        engine = self._engine(gate, executor=executor)

        iid = str(uuid.uuid4())
        intent = {"intent_id": iid, "command": "echo", "args": ["x"], "context": {}}
        r1 = engine.process_intent(intent, "1-0")
        r2 = engine.process_intent(intent, "2-0")

        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        assert r2 is not None
        self.assertEqual(r2["payload"]["receipt_kind"], "duplicate_ack")
        self.assertEqual(executor.calls, 1)
        self.assertEqual(len(engine.ledgers.receipts), 2)

    def test_missing_intent_id_causes_deny_receipt(self) -> None:
        now = "2030-03-01T00:00:00+00:00"
        exp = "2030-03-01T01:00:00+00:00"
        gate = FakeGate(self.gate_priv, [{"decision_id": "d1", "allow": False, "reason": "MISSING_OR_INVALID_INTENT_ID", "issued_at": now, "expires_at": exp}])
        engine = self._engine(gate)

        receipt = engine.process_intent({"command": "echo", "args": ["x"]}, "3-0")
        self.assertIsNotNone(receipt)
        assert receipt is not None
        self.assertFalse(receipt["payload"]["executed"])

    def test_expired_decision_blocks_execution(self) -> None:
        gate = FakeGate(
            self.gate_priv,
            [{"decision_id": "d1", "allow": True, "reason": "ALLOW", "issued_at": "2020-01-01T00:00:00+00:00", "expires_at": "2020-01-01T00:00:01+00:00"}],
        )
        executor = FakeExecutor()
        engine = self._engine(gate, executor=executor)

        receipt = engine.process_intent({"intent_id": str(uuid.uuid4()), "command": "echo", "args": ["x"], "context": {}}, "4-0")
        assert receipt is not None
        self.assertFalse(receipt["payload"]["executed"])
        self.assertEqual(executor.calls, 0)

    def test_irreversible_requires_commit_boundary_recheck(self) -> None:
        now = "2026-03-01T00:00:00+00:00"
        exp = "2030-03-01T00:00:00+00:00"
        gate = FakeGate(
            self.gate_priv,
            [
                {"decision_id": "d1", "allow": True, "reason": "ALLOW", "issued_at": now, "expires_at": exp},
                {"decision_id": "d2", "allow": False, "reason": "COMMIT_DENY", "issued_at": now, "expires_at": exp},
            ],
        )
        executor = FakeExecutor()
        engine = self._engine(gate, executor=executor)

        receipt = engine.process_intent(
            {"intent_id": str(uuid.uuid4()), "command": "echo", "args": ["x"], "irreversible": True, "context": {}},
            "5-0",
        )
        assert receipt is not None
        self.assertFalse(receipt["payload"]["executed"])
        self.assertEqual(gate.calls, 2)
        self.assertEqual(executor.calls, 0)

    def test_tampered_decision_fails_verification(self) -> None:
        now = "2026-03-01T00:00:00+00:00"
        exp = "2030-03-01T00:00:00+00:00"
        gate = FakeGate(self.gate_priv, [{"decision_id": "d1", "allow": True, "reason": "ALLOW", "issued_at": now, "expires_at": exp}])
        engine = self._engine(gate)

        # Tamper by replacing gate signature after gate call through wrapper.
        original = gate.decide

        def tampered(intent: dict[str, Any], ttl_seconds: int | None = None, commit_boundary: bool = False) -> dict[str, Any]:
            art = original(intent, ttl_seconds, commit_boundary)
            art["signature"] = "AAAA"
            return art

        gate.decide = tampered  # type: ignore[assignment]
        receipt = engine.process_intent({"intent_id": str(uuid.uuid4()), "command": "echo", "args": ["x"], "context": {}}, "6-0")
        assert receipt is not None
        self.assertFalse(receipt["payload"]["executed"])


if __name__ == "__main__":
    unittest.main()
