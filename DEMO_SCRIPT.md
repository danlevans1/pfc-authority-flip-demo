# 2-3 Minute Demo Script

## 0:00-0:30 Setup

"I will show a deterministic execution authority boundary in a small Python demo."

```bash
git clone https://github.com/danlevans1/pfc-authority-flip-demo.git
cd pfc-authority-flip-demo
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 0:30-1:30 Run the boundary decision

"This request asks for $12.4M exposure while policy allows $500K."

```bash
python run_demo.py
```

Narration points:
- Call out `STATUS: EXECUTION AUTHORITY REVOKED`
- Call out `RESULT: Trade blocked.`
- Call out `Artifact written: artifacts/decision_record.json`

## 1:30-2:20 Replay verification

"Now I replay the decision from source inputs and verify signature integrity."

```bash
python verify_replay.py
```

Narration points:
- Show `Replay verification: PASS`
- Show each check line ending in `OK`

## 2:20-3:00 Close

What this proves:
- Deterministic deny decision at the execution boundary.
- Signed, replayable artifact that can be independently verified.

What this does not prove:
- Production key custody (HSM/KMS) or tamper-proof storage.
- Full policy runtime, identity system, or compliance certification.

If you want this wrapped around your workflow as a 30-day Authority Exposure Diagnostic, reply and I’ll send the pilot plan.
