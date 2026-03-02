#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pfc_scale.config import GATE_PUBLIC_KEY, LEDGER_DIR, WORKER_DECISION_PUBLIC_KEY, WORKER_RECEIPT_PUBLIC_KEY, ensure_dirs
from pfc_scale.crypto import hash_obj, verify_payload_signature
from pfc_scale.ledger import iter_jsonl


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def get_run_id(obj: dict[str, Any] | None) -> str | None:
    if not isinstance(obj, dict):
        return None
    rid = obj.get("run_id")
    if isinstance(rid, str) and rid:
        return rid
    payload = obj.get("payload")
    if isinstance(payload, dict):
        rid2 = payload.get("run_id")
        if isinstance(rid2, str) and rid2:
            return rid2
    return None


def verify_signatures(artifact: dict[str, Any], gate_pub: bytes, worker_decision_pub: bytes) -> bool:
    payload = artifact.get("payload")
    sig = artifact.get("signature")
    kid = artifact.get("signer_kid")
    if not isinstance(payload, dict) or not isinstance(sig, str):
        return False
    if kid == "gate-v1":
        return verify_payload_signature(gate_pub, payload, sig)
    if kid == "worker-fail-closed-v1":
        return verify_payload_signature(worker_decision_pub, payload, sig)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay checker for 10,000 stability run")
    parser.add_argument("--ledger-dir", default=str(LEDGER_DIR))
    parser.add_argument("--sample-size", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--list-run-ids", action="store_true")
    args = parser.parse_args()

    ensure_dirs()
    ledger_dir = Path(args.ledger_dir)
    decisions_rows = iter_jsonl("decisions", ledger_dir)
    receipt_rows = iter_jsonl("receipts", ledger_dir)
    run_id = str(args.run_id) if args.run_id is not None else None

    if args.list_run_ids:
        counts: Counter[str] = Counter()
        for row in receipt_rows:
            rid = get_run_id(row)
            if rid is not None:
                counts[rid] += 1
        print(f"total_receipts={len(receipt_rows)}")
        print(f"unique_run_ids={len(counts)}")
        print("top_run_ids:")
        for rid, count in counts.most_common(20):
            print(f"{rid} {count}")
        sys.exit(0)

    if run_id is not None:
        filtered_receipts: list[dict[str, Any]] = []
        for row in receipt_rows:
            rid = get_run_id(row if isinstance(row, dict) else None)
            if rid == run_id:
                filtered_receipts.append(row)
        receipt_rows = filtered_receipts

    gate_pub = GATE_PUBLIC_KEY.read_bytes()
    worker_decision_pub = WORKER_DECISION_PUBLIC_KEY.read_bytes()
    worker_receipt_pub = WORKER_RECEIPT_PUBLIC_KEY.read_bytes()

    decisions_by_hash: dict[str, dict[str, Any]] = {}
    mismatches: list[str] = []

    referenced_hashes: set[str] = set()
    if run_id is not None:
        for row in receipt_rows:
            payload = row.get("payload") if isinstance(row, dict) else None
            if not isinstance(payload, dict):
                continue
            decision_hash = payload.get("decision_hash")
            if isinstance(decision_hash, str) and decision_hash:
                referenced_hashes.add(decision_hash)
            if str(payload.get("receipt_kind", "deny")) == "duplicate_ack":
                linked_original = payload.get("original_decision_hash")
                if isinstance(linked_original, str) and linked_original:
                    referenced_hashes.add(linked_original)

    filtered_decisions = decisions_rows
    if run_id is not None:
        filtered_decisions = []
        for row in decisions_rows:
            artifact = row.get("artifact") if isinstance(row, dict) else None
            row_hash = row.get("decision_hash") if isinstance(row, dict) else None
            if isinstance(row_hash, str) and row_hash in referenced_hashes:
                filtered_decisions.append(row)

    for row in filtered_decisions:
        artifact = row.get("artifact") if isinstance(row, dict) else None
        if not isinstance(artifact, dict):
            mismatches.append("decision_missing_artifact")
            continue
        payload = artifact.get("payload")
        if not isinstance(payload, dict):
            mismatches.append("decision_missing_payload")
            continue
        d_hash = hash_obj(payload)
        if row.get("decision_hash") != d_hash:
            mismatches.append(f"decision_hash_mismatch:{row.get('decision_hash')}:{d_hash}")
        if not verify_signatures(artifact, gate_pub, worker_decision_pub):
            mismatches.append(f"decision_signature_invalid:{d_hash}")
        decisions_by_hash[d_hash] = artifact

    random.seed(args.seed)
    sample = receipt_rows if len(receipt_rows) <= args.sample_size else random.sample(receipt_rows, args.sample_size)

    for row in sample:
        artifact = row if isinstance(row, dict) else {}
        payload = artifact.get("payload")
        sig = artifact.get("signature")
        if not isinstance(payload, dict) or not isinstance(sig, str):
            mismatches.append("receipt_missing_signature_or_payload")
            continue

        if not verify_payload_signature(worker_receipt_pub, payload, sig):
            mismatches.append(f"receipt_signature_invalid:{payload.get('receipt_id')}")
            continue

        decision_hash = payload.get("decision_hash")
        receipt_kind = str(payload.get("receipt_kind", "deny"))
        if receipt_kind == "duplicate_ack":
            linked_original = payload.get("original_decision_hash")
            if isinstance(linked_original, str) and linked_original:
                decision_hash = linked_original

        if not isinstance(decision_hash, str):
            mismatches.append(f"receipt_missing_decision_hash:{payload.get('receipt_id')}")
            continue

        decision_artifact = decisions_by_hash.get(decision_hash)
        if not decision_artifact:
            mismatches.append(f"receipt_decision_not_found:{payload.get('receipt_id')}")
            continue

        decision_payload = decision_artifact["payload"]
        if hash_obj(decision_payload) != decision_hash:
            mismatches.append(f"receipt_decision_hash_mismatch:{payload.get('receipt_id')}")

        if receipt_kind == "duplicate_ack":
            if bool(payload.get("executed")):
                mismatches.append(f"duplicate_ack_executed_true:{payload.get('receipt_id')}")
            if not isinstance(payload.get("original_intent_id"), str):
                mismatches.append(f"duplicate_ack_missing_original_intent:{payload.get('receipt_id')}")
            continue

        if bool(payload.get("executed")):
            if not bool(decision_payload.get("allow")):
                mismatches.append(f"executed_but_decision_denied:{payload.get('receipt_id')}")
            try:
                exec_at = parse_iso(str(payload.get("execution_at")))
                exp_at = parse_iso(str(decision_payload.get("expires_at")))
                if exec_at > exp_at:
                    mismatches.append(f"executed_after_expiry:{payload.get('receipt_id')}")
            except Exception:
                mismatches.append(f"executed_bad_timestamp:{payload.get('receipt_id')}")

    if mismatches:
        if run_id is not None:
            print(f"run_id={run_id}")
        print(f"mismatches={len(mismatches)}")
        for item in mismatches[:200]:
            print(item)
        sys.exit(1)

    if run_id is not None:
        print(f"run_id={run_id}")
    print(f"decisions={len(filtered_decisions)}")
    print(f"receipts={len(receipt_rows)}")
    print("mismatches=0")


if __name__ == "__main__":
    main()
