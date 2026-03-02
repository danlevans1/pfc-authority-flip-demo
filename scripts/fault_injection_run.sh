#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Fault injection steps for pfc_scale:

1) Kill one worker mid-run and restart
   pkill -f "pfc_scale.worker --consumer-name worker-1" || true
   python3 -m pfc_scale.worker --consumer-name worker-1 --max-messages 10000

2) Restart gate mid-run (worker must fail closed)
   pkill -f "uvicorn pfc_scale.gate_service:app" || true
   uvicorn pfc_scale.gate_service:app --host 127.0.0.1 --port 8000

After fault injection, run:
   python3 scripts/replay_check.py --sample-size 200
EOF
