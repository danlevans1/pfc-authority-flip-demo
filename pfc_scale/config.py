from __future__ import annotations

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
PFC_SCALE_DIR = ROOT_DIR / "pfc_scale"
LEDGER_DIR = PFC_SCALE_DIR / "ledger"
KEYS_DIR = PFC_SCALE_DIR / "keys"
SANDBOX_DIR = Path("/tmp/pfc_sandbox")

STREAM_NAME = os.getenv("PFC_STREAM", "pfc:intents")
CONSUMER_GROUP = os.getenv("PFC_CONSUMER_GROUP", "pfc:workers")
GATE_URL = os.getenv("PFC_GATE_URL", "http://127.0.0.1:8000")
MAX_LEDGER_BYTES = int(os.getenv("PFC_LEDGER_MAX_BYTES", str(50 * 1024 * 1024)))

GATE_PRIVATE_KEY = KEYS_DIR / "gate_private.pem"
GATE_PUBLIC_KEY = KEYS_DIR / "gate_public.pem"
WORKER_DECISION_PRIVATE_KEY = KEYS_DIR / "worker_decision_private.pem"
WORKER_DECISION_PUBLIC_KEY = KEYS_DIR / "worker_decision_public.pem"
WORKER_RECEIPT_PRIVATE_KEY = KEYS_DIR / "worker_receipt_private.pem"
WORKER_RECEIPT_PUBLIC_KEY = KEYS_DIR / "worker_receipt_public.pem"


def ensure_dirs() -> None:
    PFC_SCALE_DIR.mkdir(parents=True, exist_ok=True)
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
