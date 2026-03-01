# pfc-authority-flip-demo

Deterministic execution authority revocation demo in Python.

A simulated agent requests a $12,400,000 trade while policy allows up to $500,000. The engine deterministically revokes execution authority, blocks the trade, and emits a signed replayable artifact.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run_demo.py
```

## Expected output (example)

```text
=== Deterministic Authority Flip Demo ===
Requested exposure: $12,400,000
Policy max exposure: $500,000

STATUS: EXECUTION AUTHORITY REVOKED
REASON: Requested exposure exceeds policy limit
RESULT: Trade blocked.
Artifact written: .../artifacts/decision_record.json

Replay verification: PASS
```

## Replay verification meaning

`verify_replay.py` recomputes `policy_hash`, `request_hash`, and `decision_hash` from source inputs, then verifies the Ed25519 signature in the artifact. PASS means the decision can be replayed and cryptographically validated.

This demo signs the UTF-8 bytes of `decision_hash`.

## Notes

- No network calls or external services are used.
- Demo keys are generated locally on first run under `keys/` (gitignored).
- `decision_hash` is deterministic and excludes timestamps. `timestamp_utc` is stored separately in the artifact.

## Files

- `pfc_engine.py`: deterministic hashing, policy decisioning, key handling, signing
- `run_demo.py`: runs scenario, writes artifact, runs replay verification
- `verify_replay.py`: replay + signature checks with PASS/FAIL exit status
- `tests/test_replay.py`: blocked-path and allow-path tests
