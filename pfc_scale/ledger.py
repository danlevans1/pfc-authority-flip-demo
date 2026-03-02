from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pfc_scale.config import LEDGER_DIR, MAX_LEDGER_BYTES


class RotatingJsonlWriter:
    def __init__(self, prefix: str, base_dir: Path = LEDGER_DIR, max_bytes: int = MAX_LEDGER_BYTES, flush_every: int = 50):
        self.prefix = prefix
        self.base_dir = base_dir
        self.max_bytes = max_bytes
        self.flush_every = flush_every
        self._active_path: Path | None = None
        self._buffer: list[str] = []

    def _hourly_name(self, now: datetime) -> str:
        return f"{self.prefix}_{now.strftime('%Y%m%d_%H')}.jsonl"

    def _ensure_path(self) -> Path:
        now = datetime.now(timezone.utc)
        candidate = self.base_dir / self._hourly_name(now)
        if self._active_path is None:
            self._active_path = candidate
        elif self._active_path != candidate:
            self._flush_to_active_path()
            self._active_path = candidate
        else:
            if self._active_path.exists() and self._active_path.stat().st_size >= self.max_bytes:
                self._flush_to_active_path()
                rotated = self.base_dir / f"{self.prefix}_{now.strftime('%Y%m%d_%H%M%S')}.jsonl"
                self._active_path = rotated
        self.base_dir.mkdir(parents=True, exist_ok=True)
        return self._active_path

    def append(self, item: dict[str, Any]) -> Path:
        path = self._ensure_path()
        self._buffer.append(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        if len(self._buffer) >= self.flush_every:
            self.flush()
        return path

    def flush(self) -> None:
        if not self._buffer:
            return
        path = self._ensure_path()
        with path.open("a", encoding="utf-8") as f:
            f.write("".join(self._buffer))
        self._buffer = []

    def _flush_to_active_path(self) -> None:
        if not self._buffer or self._active_path is None:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        path = self._active_path
        with path.open("a", encoding="utf-8") as f:
            f.write("".join(self._buffer))
        self._buffer = []


class LedgerManager:
    def __init__(self) -> None:
        self.decisions = RotatingJsonlWriter("decisions")
        self.receipts = RotatingJsonlWriter("receipts")

    def write_decision(self, item: dict[str, Any]) -> Path:
        return self.decisions.append(item)

    def write_receipt(self, item: dict[str, Any]) -> Path:
        return self.receipts.append(item)

    def flush(self) -> None:
        self.decisions.flush()
        self.receipts.flush()


def iter_jsonl(prefix: str, base_dir: Path = LEDGER_DIR) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(base_dir.glob(f"{prefix}_*.jsonl")):
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
    return rows
