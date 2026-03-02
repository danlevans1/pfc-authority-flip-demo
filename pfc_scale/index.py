from __future__ import annotations

import sqlite3
from pathlib import Path

from pfc_scale.config import LEDGER_DIR


class ReceiptIndex:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (LEDGER_DIR / "index.sqlite")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                intent_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                finished_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def has_intent(self, intent_id: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM receipts WHERE intent_id = ?", (intent_id,)).fetchone()
        return row is not None

    def insert_if_absent(self, intent_id: str, run_id: str, decision_hash: str, finished_at: str) -> bool:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO receipts(intent_id, run_id, decision_hash, finished_at) VALUES (?, ?, ?, ?)",
            (intent_id, run_id, decision_hash, finished_at),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def get_decision_hash(self, intent_id: str) -> str | None:
        row = self.conn.execute("SELECT decision_hash FROM receipts WHERE intent_id = ?", (intent_id,)).fetchone()
        if row is None:
            return None
        return str(row[0])

    def close(self) -> None:
        self.conn.close()
