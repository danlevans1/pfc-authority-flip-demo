#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_DIR="$ROOT/pfc_scale/ledger/logs"
mkdir -p "$LOG_DIR"

RUN_ID="run-crash-10000-$(date -u +%Y%m%d%H%M%S)"
CRASH_AFTER=5000
TOTAL_MESSAGES=10000
RESTART_MESSAGES=$((TOTAL_MESSAGES - CRASH_AFTER + 1))
TIMEOUT_SECONDS=900
ENQUEUE_GUARD="$LOG_DIR/enqueue_${RUN_ID}.done"

cleanup() {
  local rc=$?
  if [[ -n "${WORKER2_PID:-}" ]] && kill -0 "$WORKER2_PID" 2>/dev/null; then
    kill "$WORKER2_PID" || true
    wait "$WORKER2_PID" || true
  fi
  if [[ -n "${WORKER1_PID:-}" ]] && kill -0 "$WORKER1_PID" 2>/dev/null; then
    kill "$WORKER1_PID" || true
    wait "$WORKER1_PID" || true
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
r = redis.Redis(host="127.0.0.1", port=6379, db=0, socket_connect_timeout=1, socket_timeout=1)
try:
    print(f"redis_ping={r.ping()}")
except Exception as e:
    print(f"redis_error={e}", file=sys.stderr)
    raise SystemExit(1)
PY
then
  echo "ERROR: real Redis is not reachable at 127.0.0.1:6379. Aborting (no fake Redis fallback)." >&2
  exit 1
fi

redis-cli -h 127.0.0.1 -p 6379 DEL pfc:intents >/dev/null || true

PYTHONPATH="$ROOT" ./.venv/bin/uvicorn pfc_scale.gate_service:app --host 127.0.0.1 --port 8000 >"$LOG_DIR/gate_crash_recovery.log" 2>&1 &
GATE_PID=$!
sleep 1

PYTHONPATH="$ROOT" ./.venv/bin/python -m pfc_scale.worker \
  --redis-url redis://127.0.0.1:6379/0 \
  --consumer-name worker-crash \
  --run-id "$RUN_ID" \
  --max-messages "$TOTAL_MESSAGES" \
  --crash-after "$CRASH_AFTER" \
  >"$LOG_DIR/worker_crash.log" 2>&1 &
WORKER1_PID=$!
sleep 1

if [[ -e "$ENQUEUE_GUARD" ]]; then
  echo "ERROR: enqueue guard exists for run_id=${RUN_ID}; refusing double enqueue" >&2
  exit 1
fi

PYTHONPATH="$ROOT" ./.venv/bin/python scripts/enqueue_10000_intents.py \
  --redis-url redis://127.0.0.1:6379/0 \
  --stream pfc:intents \
  --count "$TOTAL_MESSAGES" \
  --run-id "$RUN_ID" \
  | tee "$LOG_DIR/enqueue_crash_recovery.log"
touch "$ENQUEUE_GUARD"

set +e
wait "$WORKER1_PID"
WORKER1_RC=$?
set -e
echo "worker1_exit_code=$WORKER1_RC"
if [[ "$WORKER1_RC" -ne 137 ]]; then
  echo "ERROR: crash-injected worker exited with unexpected code ($WORKER1_RC)" >&2
  exit 1
fi

XPENDING_BEFORE="$(PYTHONPATH="$ROOT" ./.venv/bin/python - <<'PY'
import redis
r = redis.Redis(host="127.0.0.1", port=6379, db=0)
info = r.xpending("pfc:intents", "pfc:workers")
if isinstance(info, dict):
    print(int(info.get("pending", 0)))
elif isinstance(info, (list, tuple)) and info:
    print(int(info[0]))
else:
    print(0)
PY
)"
echo "xpending_before_restart=${XPENDING_BEFORE}"

PYTHONPATH="$ROOT" ./.venv/bin/python -m pfc_scale.worker \
  --redis-url redis://127.0.0.1:6379/0 \
  --consumer-name worker-recover \
  --run-id "$RUN_ID" \
  --max-messages "$RESTART_MESSAGES" \
  >"$LOG_DIR/worker_recovery.log" 2>&1 &
WORKER2_PID=$!
wait "$WORKER2_PID"

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
while true; do
  METRICS="$(
    RUN_ID="$RUN_ID" PYTHONPATH="$ROOT" ./.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
import redis

run_id = os.environ["RUN_ID"]
ledger_dir = Path("pfc_scale/ledger")

def get_run_id(obj):
    if not isinstance(obj, dict):
        return None
    rid = obj.get("run_id")
    if isinstance(rid, str) and rid:
        return rid
    payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    rid2 = payload.get("run_id")
    if isinstance(rid2, str) and rid2:
        return rid2
    return None

rows = 0
message_ids = set()
for path in sorted(ledger_dir.glob("receipts_*.jsonl")):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if get_run_id(obj) != run_id:
                continue
            rows += 1
            payload = obj.get("payload")
            if isinstance(payload, dict):
                mid = payload.get("message_id")
                if isinstance(mid, str) and mid:
                    message_ids.add(mid)

r = redis.Redis(host="127.0.0.1", port=6379, db=0)
info = r.xpending("pfc:intents", "pfc:workers")
if isinstance(info, dict):
    pending = int(info.get("pending", 0))
elif isinstance(info, (list, tuple)) and info:
    pending = int(info[0])
else:
    pending = 0

print(f"receipts_rows_for_run={rows}")
print(f"receipts_for_run={len(message_ids)}")
print(f"unique_message_ids_for_run={len(message_ids)}")
print(f"xpending={pending}")
PY
  )"
  echo "$METRICS" > "$LOG_DIR/run_crash_recovery_metrics.log"

  RECEIPTS_FOR_RUN="$(echo "$METRICS" | awk -F= '/^receipts_for_run=/{print $2}')"
  XPENDING_AFTER="$(echo "$METRICS" | awk -F= '/^xpending=/{print $2}')"
  if [[ "$RECEIPTS_FOR_RUN" == "$TOTAL_MESSAGES" ]] && [[ "$XPENDING_AFTER" == "0" ]]; then
    break
  fi
  if [[ "$(date +%s)" -ge "$deadline" ]]; then
    echo "ERROR: timeout waiting for completion criteria (receipts_for_run=${RECEIPTS_FOR_RUN} xpending=${XPENDING_AFTER})" >&2
    exit 1
  fi
  sleep 2
done
echo "xpending_after_completion=${XPENDING_AFTER}"

PYTHONPATH="$ROOT" ./.venv/bin/python scripts/replay_check.py --run-id "$RUN_ID" --sample-size 200 | tee "$LOG_DIR/replay_crash_recovery.log"

REPLAY_MISMATCHES="$(awk -F= '/^mismatches=/{print $2}' "$LOG_DIR/replay_crash_recovery.log" | tail -n 1)"
if [[ -z "$REPLAY_MISMATCHES" ]]; then
  echo "ERROR: replay mismatches value not found" >&2
  exit 1
fi
if [[ "$REPLAY_MISMATCHES" != "0" ]]; then
  echo "ERROR: replay check failed" >&2
  exit 1
fi

echo "run_id=${RUN_ID}"
echo "worker log crash marker:"
grep -n "CRASH_INJECTED" "$LOG_DIR/worker_crash.log" | tail -n 1
echo "worker final summary:"
grep -E '^(run_id=|total_messages=|unique_intents=|receipts_written=|duplicate_messages=|allowed_executed=|denied=|malformed=|expired_blocked=|mismatches=)' "$LOG_DIR/worker_recovery.log"

RECEIPTS_FOR_RUN="$(awk -F= '/^receipts_for_run=/{print $2}' "$LOG_DIR/run_crash_recovery_metrics.log" | tail -n 1)"
UNIQUE_MESSAGE_IDS_FOR_RUN="$(awk -F= '/^unique_message_ids_for_run=/{print $2}' "$LOG_DIR/run_crash_recovery_metrics.log" | tail -n 1)"
XPENDING_AFTER="$(awk -F= '/^xpending=/{print $2}' "$LOG_DIR/run_crash_recovery_metrics.log" | tail -n 1)"
PASS="false"
if [[ "$RECEIPTS_FOR_RUN" == "$TOTAL_MESSAGES" ]] && [[ "$XPENDING_AFTER" == "0" ]] && [[ "$REPLAY_MISMATCHES" == "0" ]]; then
  PASS="true"
fi

echo "=== RUN-LEVEL PROOF ==="
echo "run_id=${RUN_ID}"
echo "enqueued_messages=${TOTAL_MESSAGES}"
echo "receipts_for_run=${RECEIPTS_FOR_RUN}"
echo "unique_message_ids_for_run=${UNIQUE_MESSAGE_IDS_FOR_RUN}"
echo "xpending_after_completion=${XPENDING_AFTER}"
echo "replay_mismatches=${REPLAY_MISMATCHES}"
echo "PASS=${PASS}"
echo "========================"

if [[ "$PASS" != "true" ]]; then
  echo "ERROR: run-level proof block did not meet acceptance criteria" >&2
  exit 1
fi
