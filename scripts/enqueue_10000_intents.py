#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import uuid
from collections import Counter
from typing import Any

import redis

STREAM = "pfc:intents"


def allowed_intent(intent_id: str, run_id: str) -> dict[str, Any]:
    choice = random.choice(["echo", "ls", "cat"])
    if choice == "echo":
        args = ["hello", intent_id[:8]]
    elif choice == "ls":
        args = ["."]
    else:
        args = ["README.txt"]
    return {
        "intent_id": intent_id,
        "command": choice,
        "args": args,
        "irreversible": False,
        "context": {"run_id": run_id},
    }


def denied_intent(intent_id: str, run_id: str) -> dict[str, Any]:
    command, args = random.choice(
        [
            ("rm", ["-rf", "/tmp"]),
            ("curl", ["https://example.com"]),
            ("sudo", ["whoami"]),
            ("bash", ["-lc", "echo nope"]),
            ("cat", ["/etc/passwd"]),
        ]
    )
    return {
        "intent_id": intent_id,
        "command": command,
        "args": args,
        "irreversible": False,
        "context": {"run_id": run_id},
    }


def malformed_intent(run_id: str) -> dict[str, Any]:
    variant = random.randint(1, 4)
    if variant == 1:
        return {"command": "echo", "args": ["missing-id"], "context": {"run_id": run_id}}
    if variant == 2:
        return {"intent_id": "not-a-uuid", "command": "echo", "args": ["bad-id"], "context": {"run_id": run_id}}
    if variant == 3:
        return {"intent_id": str(uuid.uuid4()), "args": ["missing-command"], "context": {"run_id": run_id}}
    return {"intent_id": str(uuid.uuid4()), "command": "echo", "args": "not-a-list", "context": {"run_id": run_id}}


def build_intents(total: int, seed: int, run_id: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    random.seed(seed)
    allowed_n = int(total * 0.20)
    denied_n = int(total * 0.70)
    malformed_n = total - allowed_n - denied_n

    intents: list[dict[str, Any]] = []
    valid_ids: list[str] = []

    for _ in range(allowed_n):
        iid = str(uuid.uuid4())
        valid_ids.append(iid)
        intents.append(allowed_intent(iid, run_id))

    for _ in range(denied_n):
        iid = str(uuid.uuid4())
        valid_ids.append(iid)
        intents.append(denied_intent(iid, run_id))

    for _ in range(malformed_n):
        intents.append(malformed_intent(run_id))

    random.shuffle(intents)

    duplicate_count = max(1, int(total * 0.01))
    duplicate_indices = random.sample(range(total), k=duplicate_count)
    for idx in duplicate_indices:
        intents[idx]["intent_id"] = random.choice(valid_ids)

    irreversible_count = max(1, int(total * 0.01))
    irreversible_indices = random.sample(range(total), k=irreversible_count)
    for idx in irreversible_indices:
        if isinstance(intents[idx].get("intent_id"), str):
            intents[idx]["irreversible"] = True

    forced_expiry_count = max(1, int(total * 0.01))
    forced_expiry_indices = random.sample(range(total), k=forced_expiry_count)
    for idx in forced_expiry_indices:
        if not isinstance(intents[idx].get("context"), dict):
            intents[idx]["context"] = {}
        intents[idx]["context"]["delay_before_commit_ms"] = 2500
        intents[idx]["context"]["ttl_seconds"] = 1

    meta = {
        "allowed_n": allowed_n,
        "denied_n": denied_n,
        "malformed_n": malformed_n,
        "duplicate_count": duplicate_count,
        "irreversible_count": irreversible_count,
        "forced_expiry_count": forced_expiry_count,
    }
    return intents, meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Enqueue 10,000 intents to Redis stream")
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0")
    parser.add_argument("--stream", default=STREAM)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-id", default="scale-10000")
    args = parser.parse_args()

    r = redis.Redis.from_url(args.redis_url, decode_responses=False)

    intents, meta = build_intents(total=args.count, seed=args.seed, run_id=args.run_id)

    counts = Counter()
    for intent in intents:
        iid = intent.get("intent_id")
        if not isinstance(iid, str) or "-" not in iid:
            counts["malformed"] += 1
        elif intent.get("command") in {"echo", "ls", "cat"} and intent.get("command") != "cat" or (
            intent.get("command") == "cat" and isinstance(intent.get("args"), list) and intent["args"] and not str(intent["args"][0]).startswith("/")
        ):
            counts["maybe_allowed"] += 1
        else:
            counts["likely_denied"] += 1

    for intent in intents:
        r.xadd(args.stream, {"intent": json.dumps(intent, separators=(",", ":"), ensure_ascii=True)})

    print(f"enqueued={len(intents)} stream={args.stream}")
    print(
        f"configured_allowed={meta['allowed_n']} configured_denied={meta['denied_n']} "
        f"configured_malformed={meta['malformed_n']}"
    )
    print(
        f"duplicates_intent_id={meta['duplicate_count']} irreversible={meta['irreversible_count']} "
        f"forced_expiry={meta['forced_expiry_count']}"
    )
    print(f"observed_malformed={counts['malformed']} observed_maybe_allowed={counts['maybe_allowed']} observed_likely_denied={counts['likely_denied']}")


if __name__ == "__main__":
    main()
