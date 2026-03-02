from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from pfc_scale.config import GATE_PRIVATE_KEY, GATE_PUBLIC_KEY, ensure_dirs
from pfc_scale.crypto import ensure_ed25519_keypair, sign_payload

app = FastAPI(title="PFC Gate", version="1.0")

GATE_KID = "gate-v1"
GATE_PRIVATE_PEM: bytes


class DecisionRequest(BaseModel):
    intent: dict[str, Any]
    ttl_seconds: int | None = None
    commit_boundary: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _path_safe(arg: str) -> bool:
    return not (arg.startswith("/") or ".." in arg)


def evaluate_intent(intent: dict[str, Any], ttl_seconds: int | None, commit_boundary: bool) -> dict[str, Any]:
    now = _now()
    ttl = int(ttl_seconds if ttl_seconds is not None else 300)
    ttl = max(1, min(ttl, 3600))

    intent_id = intent.get("intent_id")
    cmd = intent.get("command")
    args = intent.get("args") or []
    context = intent.get("context") if isinstance(intent.get("context"), dict) else {}
    irreversible = bool(intent.get("irreversible", False))

    allow = False
    reason = "DENY_BY_DEFAULT"

    if not _is_uuid(intent_id):
        reason = "MISSING_OR_INVALID_INTENT_ID"
    elif not isinstance(cmd, str):
        reason = "MISSING_COMMAND"
    elif cmd in {"rm", "curl", "sudo", "bash", "sh"}:
        reason = "COMMAND_DENIED"
    elif cmd not in {"echo", "ls", "cat"}:
        reason = "COMMAND_NOT_ALLOWLISTED"
    elif not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        reason = "INVALID_ARGS"
    elif cmd in {"ls", "cat"} and any(not _path_safe(x) for x in args):
        reason = "PATH_OUTSIDE_SANDBOX"
    else:
        allow = True
        reason = "ALLOW"

    payload = {
        "decision_id": str(uuid.uuid4()),
        "run_id": str(context.get("run_id", "default-run")),
        "intent_id": intent_id,
        "allow": allow,
        "reason": reason,
        "command": cmd,
        "args": args,
        "irreversible": irreversible,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(seconds=ttl)),
        "commit_boundary": bool(commit_boundary),
        "source": "gate",
    }
    signature = sign_payload(GATE_PRIVATE_PEM, payload)
    return {
        "payload": payload,
        "signature": signature,
        "signature_alg": "ed25519",
        "signer_kid": GATE_KID,
    }


@app.on_event("startup")
def startup() -> None:
    global GATE_PRIVATE_PEM
    ensure_dirs()
    GATE_PRIVATE_PEM, _ = ensure_ed25519_keypair(GATE_PRIVATE_KEY, GATE_PUBLIC_KEY)


@app.post("/decide")
def decide(req: DecisionRequest) -> dict[str, Any]:
    return evaluate_intent(req.intent, req.ttl_seconds, req.commit_boundary)
