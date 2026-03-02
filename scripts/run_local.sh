#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_DIR="$ROOT/pfc_scale/ledger/logs"
mkdir -p "$LOG_DIR"

cleanup() {
  local rc=$?
  if [[ -n "${WORKER_PID:-}" ]] && kill -0 "$WORKER_PID" 2>/dev/null; then
    kill "$WORKER_PID" || true
    wait "$WORKER_PID" || true
  fi
  if [[ -n "${GATE_PID:-}" ]] && kill -0 "$GATE_PID" 2>/dev/null; then
    kill "$GATE_PID" || true
    wait "$GATE_PID" || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

python3 -m venv .venv
source .venv/bin/activate
pip install -r pfc_scale/requirements.txt >/dev/null

if ! PYTHONPATH="$ROOT" ./.venv/bin/python - <<'PY'
import sys
import redis

try:
    r = redis.Redis(host="127.0.0.1", port=6379, db=0, socket_connect_timeout=1, socket_timeout=1)
    r.ping()
    print("redis_ok")
except Exception as e:
    print(f"redis_error={e}", file=sys.stderr)
    raise SystemExit(1)
PY
then
  echo "ERROR: real Redis is not reachable at 127.0.0.1:6379. Aborting (no fake Redis fallback)." >&2
  if command -v redis-server >/dev/null 2>&1 || command -v brew >/dev/null 2>&1; then
    echo "Start Redis via Homebrew (macOS):" >&2
    echo "  brew install redis" >&2
    echo "  brew services start redis" >&2
    echo "  redis-cli ping" >&2
  fi
  if command -v docker >/dev/null 2>&1; then
    echo "If using Docker, ensure Docker Desktop is running and context/socket access works, then run:" >&2
    echo "  docker run -d --rm -p 6379:6379 --name pfc-redis redis:7" >&2
  fi
  exit 1
fi

PYTHONPATH="$ROOT" ./.venv/bin/uvicorn pfc_scale.gate_service:app --host 127.0.0.1 --port 8000 >"$LOG_DIR/gate.log" 2>&1 &
GATE_PID=$!

sleep 1

PYTHONPATH="$ROOT" ./.venv/bin/python -m pfc_scale.worker --redis-url redis://127.0.0.1:6379/0 --consumer-name worker-1 --run-id run-10000 --max-messages 10000 >"$LOG_DIR/worker.log" 2>&1 &
WORKER_PID=$!

sleep 1

PYTHONPATH="$ROOT" ./.venv/bin/python scripts/enqueue_10000_intents.py --redis-url redis://127.0.0.1:6379/0 --stream pfc:intents --count 10000 | tee "$LOG_DIR/enqueue.log"

wait "$WORKER_PID"

PYTHONPATH="$ROOT" ./.venv/bin/python scripts/replay_check.py --sample-size 200 | tee "$LOG_DIR/replay.log"

if grep -q '^mismatches=0$' "$LOG_DIR/replay.log"; then
  echo "FINAL PASS"
else
  echo "FINAL FAIL"
  exit 1
fi
