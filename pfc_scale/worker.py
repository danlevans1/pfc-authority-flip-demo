from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import redis
import requests

from pfc_scale.config import (
    CONSUMER_GROUP,
    GATE_PRIVATE_KEY,
    GATE_PUBLIC_KEY,
    GATE_URL,
    SANDBOX_DIR,
    STREAM_NAME,
    WORKER_DECISION_PRIVATE_KEY,
    WORKER_DECISION_PUBLIC_KEY,
    WORKER_RECEIPT_PRIVATE_KEY,
    WORKER_RECEIPT_PUBLIC_KEY,
    ensure_dirs,
)
from pfc_scale.crypto import ensure_ed25519_keypair, hash_obj, sign_payload, verify_payload_signature
from pfc_scale.index import ReceiptIndex
from pfc_scale.ledger import LedgerManager


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


class GateClient:
    def __init__(self, gate_url: str):
        self.gate_url = gate_url.rstrip("/")

    def decide(self, intent: dict[str, Any], ttl_seconds: int | None = None, commit_boundary: bool = False) -> dict[str, Any]:
        payload = {"intent": intent, "ttl_seconds": ttl_seconds, "commit_boundary": commit_boundary}
        resp = requests.post(f"{self.gate_url}/decide", json=payload, timeout=2.0)
        resp.raise_for_status()
        return resp.json()


class CommandExecutor:
    def __init__(self, sandbox_dir: Path):
        self.sandbox_dir = sandbox_dir
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve_safe_path(base: Path, value: str) -> Path:
        candidate = (base / value).resolve()
        if not str(candidate).startswith(str(base.resolve())):
            raise ValueError("path_outside_sandbox")
        return candidate

    def run(self, command: str, args: list[str]) -> tuple[bool, str]:
        if command == "echo":
            cp = subprocess.run(["echo", *args], capture_output=True, text=True, cwd=self.sandbox_dir)
            return cp.returncode == 0, cp.stdout.strip()

        if command == "ls":
            safe_args: list[str] = []
            if args:
                for arg in args:
                    safe_args.append(str(self._resolve_safe_path(self.sandbox_dir, arg)))
            cp = subprocess.run(["ls", *safe_args], capture_output=True, text=True, cwd=self.sandbox_dir)
            return cp.returncode == 0, cp.stdout.strip() or cp.stderr.strip()

        if command == "cat":
            if len(args) != 1:
                return False, "cat_requires_one_path"
            safe_path = self._resolve_safe_path(self.sandbox_dir, args[0])
            cp = subprocess.run(["cat", str(safe_path)], capture_output=True, text=True, cwd=self.sandbox_dir)
            return cp.returncode == 0, cp.stdout.strip() or cp.stderr.strip()

        return False, "command_not_allowlisted"


@dataclass
class WorkerStats:
    total_messages: int = 0
    unique_intents: int = 0
    receipts_written: int = 0
    duplicate_messages: int = 0
    allowed_executed: int = 0
    denied: int = 0
    malformed: int = 0
    expired_blocked: int = 0


class WorkerEngine:
    def __init__(
        self,
        run_id: str,
        gate_client: GateClient,
        index: ReceiptIndex,
        ledgers: LedgerManager,
        executor: CommandExecutor,
        gate_public_pem: bytes,
        local_decision_private_pem: bytes,
        local_decision_public_pem: bytes,
        receipt_private_pem: bytes,
    ):
        self.run_id = run_id
        self.gate_client = gate_client
        self.index = index
        self.ledgers = ledgers
        self.executor = executor
        self.gate_public_pem = gate_public_pem
        self.local_decision_private_pem = local_decision_private_pem
        self.local_decision_public_pem = local_decision_public_pem
        self.receipt_private_pem = receipt_private_pem
        self.stats = WorkerStats()

    def _verify_decision(self, artifact: dict[str, Any]) -> bool:
        payload = artifact.get("payload")
        sig = artifact.get("signature")
        signer_kid = artifact.get("signer_kid")
        if not isinstance(payload, dict) or not isinstance(sig, str) or not isinstance(signer_kid, str):
            return False
        if signer_kid == "gate-v1":
            return verify_payload_signature(self.gate_public_pem, payload, sig)
        if signer_kid == "worker-fail-closed-v1":
            return verify_payload_signature(self.local_decision_public_pem, payload, sig)
        return False

    def _local_fail_closed_decision(self, intent: dict[str, Any], reason: str) -> dict[str, Any]:
        now = utc_now()
        payload = {
            "decision_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "intent_id": intent.get("intent_id"),
            "allow": False,
            "reason": reason,
            "command": intent.get("command"),
            "args": intent.get("args") if isinstance(intent.get("args"), list) else [],
            "irreversible": bool(intent.get("irreversible", False)),
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=300)),
            "commit_boundary": False,
            "source": "worker_fail_closed",
        }
        return {
            "payload": payload,
            "signature": sign_payload(self.local_decision_private_pem, payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-fail-closed-v1",
        }

    def _make_receipt(
        self,
        intent_id: str,
        decision_hash: str,
        executed: bool,
        reason: str,
        execution_at: str,
        decision_expires_at: str,
        output: str,
        message_id: str,
        receipt_kind: str,
        original_intent_id: str | None = None,
        original_receipt_hash: str | None = None,
        original_decision_hash: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "receipt_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "intent_id": intent_id,
            "decision_hash": decision_hash,
            "executed": executed,
            "reason": reason,
            "execution_at": execution_at,
            "decision_expires_at": decision_expires_at,
            "message_id": message_id,
            "output": output,
            "finished_at": iso(utc_now()),
            "receipt_kind": receipt_kind,
            "original_intent_id": original_intent_id,
            "original_receipt_hash": original_receipt_hash,
            "original_decision_hash": original_decision_hash,
        }
        return {
            "payload": payload,
            "signature": sign_payload(self.receipt_private_pem, payload),
            "signature_alg": "ed25519",
            "signer_kid": "worker-receipt-v1",
        }

    def _gate_decide(self, intent: dict[str, Any], ttl_seconds: int | None = None, commit_boundary: bool = False) -> dict[str, Any]:
        try:
            artifact = self.gate_client.decide(intent=intent, ttl_seconds=ttl_seconds, commit_boundary=commit_boundary)
            if not self._verify_decision(artifact):
                return self._local_fail_closed_decision(intent, "DECISION_SIGNATURE_INVALID")
            return artifact
        except Exception:
            return self._local_fail_closed_decision(intent, "GATE_UNREACHABLE_FAIL_CLOSED")

    def process_intent(self, intent: dict[str, Any], message_id: str = "local-test") -> dict[str, Any] | None:
        self.stats.total_messages += 1
        context = intent.get("context") if isinstance(intent.get("context"), dict) else {}
        intent_id = intent.get("intent_id")

        if not is_uuid(intent_id):
            self.stats.malformed += 1
            intent_id = f"missing:{message_id}"

        if not str(intent_id).startswith("missing:") and self.index.has_intent(str(intent_id)):
            self.stats.duplicate_messages += 1
            original_decision_hash = self.index.get_decision_hash(str(intent_id)) or ""
            now = utc_now()
            duplicate_receipt = self._make_receipt(
                intent_id=str(intent_id),
                decision_hash=original_decision_hash,
                executed=False,
                reason="DUPLICATE_INTENT_ACK",
                execution_at=iso(now),
                decision_expires_at="",
                output="",
                message_id=message_id,
                receipt_kind="duplicate_ack",
                original_intent_id=str(intent_id),
                original_receipt_hash=None,
                original_decision_hash=original_decision_hash,
            )
            self.ledgers.write_receipt(duplicate_receipt)
            self.stats.receipts_written += 1
            return duplicate_receipt

        ttl_seconds = context.get("ttl_seconds") if isinstance(context.get("ttl_seconds"), int) else None
        first_decision = self._gate_decide(intent, ttl_seconds=ttl_seconds, commit_boundary=False)
        first_payload = first_decision["payload"]
        first_hash = hash_obj(first_payload)
        self.ledgers.write_decision({"decision_hash": first_hash, "artifact": first_decision})

        if not self._verify_decision(first_decision):
            first_payload["allow"] = False
            first_payload["reason"] = "UNVERIFIED_DECISION_FAIL_CLOSED"

        commit_decision = first_decision
        commit_hash = first_hash

        if bool(intent.get("irreversible", False)):
            if first_payload.get("allow"):
                second_ttl = random.randint(60, 120)
                second_intent = dict(intent)
                second_context = dict(context)
                second_context["commit_boundary"] = True
                second_intent["context"] = second_context
                second_decision = self._gate_decide(second_intent, ttl_seconds=second_ttl, commit_boundary=True)
                second_payload = second_decision["payload"]
                second_hash = hash_obj(second_payload)
                self.ledgers.write_decision({"decision_hash": second_hash, "artifact": second_decision})
                commit_decision = second_decision
                commit_hash = second_hash

        delay_ms = int(context.get("delay_before_commit_ms", 0)) if isinstance(context.get("delay_before_commit_ms"), int) else 0
        if delay_ms > 0:
            time.sleep(max(0, delay_ms) / 1000.0)

        payload = commit_decision["payload"]
        now = utc_now()
        try:
            expires_at = parse_iso(str(payload.get("expires_at")))
            is_expired = now > expires_at
        except Exception:
            expires_at = now - timedelta(seconds=1)
            is_expired = True

        command = payload.get("command")
        args = payload.get("args") if isinstance(payload.get("args"), list) else []

        executed = False
        reason = "DENIED"
        output = ""

        if is_expired:
            self.stats.expired_blocked += 1
            reason = "DECISION_EXPIRED"
        elif bool(payload.get("allow")):
            ok, out = self.executor.run(str(command), [str(a) for a in args])
            if ok:
                executed = True
                reason = "EXECUTED"
                output = out
            else:
                reason = f"EXECUTION_BLOCKED:{out}"
                output = out
        else:
            reason = str(payload.get("reason", "DENIED"))

        receipt = self._make_receipt(
            intent_id=str(intent_id),
            decision_hash=commit_hash,
            executed=executed,
            reason=reason,
            execution_at=iso(now),
            decision_expires_at=str(payload.get("expires_at")),
            output=output,
            message_id=message_id,
            receipt_kind="execution" if executed else "deny",
        )

        inserted = self.index.insert_if_absent(str(intent_id), self.run_id, commit_hash, receipt["payload"]["finished_at"])
        if not inserted:
            self.stats.duplicate_messages += 1
            duplicate_receipt = self._make_receipt(
                intent_id=str(intent_id),
                decision_hash=commit_hash,
                executed=False,
                reason="DUPLICATE_INTENT_ACK",
                execution_at=iso(now),
                decision_expires_at=str(payload.get("expires_at")),
                output="",
                message_id=message_id,
                receipt_kind="duplicate_ack",
                original_intent_id=str(intent_id),
                original_receipt_hash=None,
                original_decision_hash=commit_hash,
            )
            self.ledgers.write_receipt(duplicate_receipt)
            self.stats.receipts_written += 1
            return duplicate_receipt

        self.ledgers.write_receipt(receipt)
        self.stats.unique_intents += 1
        self.stats.receipts_written += 1
        if executed:
            self.stats.allowed_executed += 1
        else:
            self.stats.denied += 1
        return receipt


def decode_redis_fields(fields: dict[bytes, bytes]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for k, v in fields.items():
        dk = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
        dv = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
        decoded[dk] = dv
    return decoded


def pending_count(r: redis.Redis, stream: str, group: str) -> int:
    info = r.xpending(stream, group)
    if isinstance(info, dict):
        return int(info.get("pending", 0))
    if isinstance(info, (list, tuple)) and info:
        return int(info[0])
    return 0


def reclaim_pending_messages(
    r: redis.Redis,
    stream: str,
    group: str,
    consumer: str,
    min_idle_ms: int = 60000,
    count: int = 100,
) -> list[tuple[Any, dict[bytes, bytes]]]:
    claimed: list[tuple[Any, dict[bytes, bytes]]] = []
    try:
        start_id: str | bytes = "0-0"
        seen: set[str | bytes] = set()
        while True:
            resp = r.xautoclaim(
                name=stream,
                groupname=group,
                consumername=consumer,
                min_idle_time=min_idle_ms,
                start_id=start_id,
                count=count,
            )
            if not isinstance(resp, (list, tuple)) or len(resp) < 2:
                break
            next_start = resp[0]
            messages = resp[1]
            if isinstance(messages, list) and messages:
                claimed.extend(messages)
            if next_start in seen or not messages or next_start in ("0-0", b"0-0"):
                break
            seen.add(next_start)
            start_id = next_start
        return claimed
    except Exception:
        # Fallback for older Redis/redis-py compatibility.
        pending = r.xpending_range(stream, group, min="-", max="+", count=count, idle=min_idle_ms)
        message_ids: list[Any] = []
        for item in pending:
            if not isinstance(item, dict):
                continue
            mid = item.get("message_id", item.get(b"message_id"))
            if mid is not None:
                message_ids.append(mid)
        if not message_ids:
            return claimed
        claimed_items = r.xclaim(stream, group, consumer, min_idle_ms, message_ids)
        if isinstance(claimed_items, list):
            claimed.extend(claimed_items)
        return claimed


def maybe_inject_crash(
    crash_after: int,
    handled_count: int,
    run_id: str,
    flush_fn: Callable[[], None],
    exit_fn: Callable[[int], None] = os._exit,
) -> None:
    if crash_after and handled_count >= crash_after:
        flush_fn()
        print(f"CRASH_INJECTED after={handled_count} run_id={run_id}", flush=True)
        exit_fn(137)


def print_summary(run_id: str, stats: WorkerStats, target: int) -> None:
    print(f"run_id={run_id}")
    print(f"total_messages={stats.total_messages}")
    print(f"unique_intents={stats.unique_intents}")
    print(f"receipts_written={stats.receipts_written}")
    print(f"duplicate_messages={stats.duplicate_messages}")
    print(f"allowed_executed={stats.allowed_executed}")
    print(f"denied={stats.denied}")
    print(f"malformed={stats.malformed}")
    print(f"expired_blocked={stats.expired_blocked}")
    print("mismatches=0")


def build_engine(run_id: str, gate_url: str) -> WorkerEngine:
    ensure_dirs()
    _, gate_pub = ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)
    local_decision_priv, local_decision_pub = ensure_ed25519_keypair(WORKER_DECISION_PRIVATE_KEY, WORKER_DECISION_PUBLIC_KEY)
    receipt_priv, _ = ensure_ed25519_keypair(WORKER_RECEIPT_PRIVATE_KEY, WORKER_RECEIPT_PUBLIC_KEY)

    return WorkerEngine(
        run_id=run_id,
        gate_client=GateClient(gate_url),
        index=ReceiptIndex(),
        ledgers=LedgerManager(),
        executor=CommandExecutor(SANDBOX_DIR),
        gate_public_pem=gate_pub,
        local_decision_private_pem=local_decision_priv,
        local_decision_public_pem=local_decision_pub,
        receipt_private_pem=receipt_priv,
    )


def worker_loop(
    redis_url: str,
    consumer_name: str,
    run_id: str,
    max_messages: int,
    crash_after: int = 0,
    reclaim_idle_ms: int = 60000,
) -> None:
    engine = build_engine(run_id=run_id, gate_url=GATE_URL)
    r = redis.Redis.from_url(redis_url, decode_responses=False)

    try:
        r.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0-0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise

    processed = 0
    last_reclaim = 0.0

    def handle_message(message_id_raw: Any, fields: dict[bytes, bytes]) -> bool:
        nonlocal processed
        message_id = message_id_raw.decode("utf-8") if isinstance(message_id_raw, (bytes, bytearray)) else str(message_id_raw)
        decoded = decode_redis_fields(fields)
        raw = decoded.get("intent", "{}")
        try:
            intent = json.loads(raw)
            if not isinstance(intent, dict):
                intent = {}
        except Exception:
            intent = {}

        receipt = engine.process_intent(intent, message_id=message_id)
        if receipt is None:
            return False

        processed += 1
        maybe_inject_crash(crash_after, processed, run_id, engine.ledgers.flush)
        r.xack(STREAM_NAME, CONSUMER_GROUP, message_id_raw)
        return True

    reclaimed_at_start = reclaim_pending_messages(
        r,
        STREAM_NAME,
        CONSUMER_GROUP,
        consumer_name,
        min_idle_ms=reclaim_idle_ms,
    )
    for message_id_b, fields in reclaimed_at_start:
        handle_message(message_id_b, fields)
        if max_messages and processed >= max_messages:
            break

    while True:
        if max_messages and processed >= max_messages:
            break

        now_ts = time.time()
        if now_ts - last_reclaim >= 5:
            reclaimed = reclaim_pending_messages(
                r,
                STREAM_NAME,
                CONSUMER_GROUP,
                consumer_name,
                min_idle_ms=reclaim_idle_ms,
            )
            last_reclaim = now_ts
            for message_id_b, fields in reclaimed:
                handle_message(message_id_b, fields)
                if max_messages and processed >= max_messages:
                    break
            if max_messages and processed >= max_messages:
                break

        if pending_count(r, STREAM_NAME, CONSUMER_GROUP) > 2000:
            time.sleep(random.uniform(0.1, 0.25))

        events = r.xreadgroup(
            groupname=CONSUMER_GROUP,
            consumername=consumer_name,
            streams={STREAM_NAME: ">"},
            count=50,
            block=2000,
        )
        if not events:
            continue

        for _, messages in events:
            for message_id_b, fields in messages:
                handle_message(message_id_b, fields)
                if max_messages and processed >= max_messages:
                    break
            if max_messages and processed >= max_messages:
                break

    engine.ledgers.flush()
    print_summary(run_id, engine.stats, max_messages or processed)


def main() -> None:
    parser = argparse.ArgumentParser(description="PFC scale worker")
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0")
    parser.add_argument("--consumer-name", default="worker-1")
    parser.add_argument("--run-id", default=f"run-{int(time.time())}")
    parser.add_argument("--max-messages", type=int, default=0)
    parser.add_argument("--crash-after", type=int, default=0)
    parser.add_argument("--reclaim-idle-ms", type=int, default=60000)
    args = parser.parse_args()
    worker_loop(args.redis_url, args.consumer_name, args.run_id, args.max_messages, args.crash_after, args.reclaim_idle_ms)


if __name__ == "__main__":
    main()
