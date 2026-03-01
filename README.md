[![CI](https://github.com/danlevans1/pfc-authority-flip-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/danlevans1/pfc-authority-flip-demo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# pfc-authority-flip-demo

Deterministic execution authority revocation demo in Python.

A simulated agent requests a $12,400,000 trade while policy allows up to $500,000. The engine deterministically revokes execution authority, blocks the trade, and emits a signed replayable artifact.

## Run in under a minute

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_demo.py
python verify_replay.py
python -m unittest
```

## Expected output (example)

```text
=== Deterministic Authority Flip Demo ===
Requested exposure: $12,400,000
Policy max exposure: $500,000
STATUS: EXECUTION AUTHORITY REVOKED
REASON: Requested exposure exceeds policy limit
RESULT: Trade blocked.
Artifact written: artifacts/decision_record.json
Replay verification: PASS
```

```text
Replay verification: PASS
- policy_hash match: OK
- request_hash match: OK
- decision_core match: OK
- decision_hash match: OK
- public_key_fingerprint match: OK
- signature verify: OK
```

## Air-gapped / offline install

```bash
# On an internet-connected machine
python3 -m venv .venv_tmp && source .venv_tmp/bin/activate
python -m pip install --upgrade pip
mkdir -p vendor
python -m pip download -r requirements.txt -d vendor
deactivate

# On the offline machine
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --no-index --find-links vendor -r requirements.txt
```

- `keys/` is generated on first run and is gitignored.
- `decision_hash` excludes timestamps, so replay hash inputs are deterministic.
- Signature is over `decision_hash` UTF-8 bytes.

## Replay verification meaning

`verify_replay.py` recomputes `policy_hash`, `request_hash`, and `decision_hash` from source inputs, then verifies the Ed25519 signature in the artifact. PASS means the decision can be replayed and cryptographically validated.

## Notes

- No network calls or external services are used.
- `timestamp_utc` is stored separately in the artifact and does not affect `decision_hash`.

## Files

- `pfc_engine.py`: deterministic hashing, policy decisioning, key handling, signing
- `run_demo.py`: runs scenario, writes artifact, runs replay verification
- `verify_replay.py`: replay + signature checks with PASS/FAIL exit status
- `tests/test_replay.py`: blocked-path and allow-path tests
