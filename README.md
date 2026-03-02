[![CI](https://github.com/danlevans1/pfc-authority-flip-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/danlevans1/pfc-authority-flip-demo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# pfc-authority-flip-demo

Deterministic execution authority revocation demo in Python.

A simulated agent requests a $12,400,000 trade while policy allows up to $500,000. The engine deterministically revokes execution authority, blocks the trade, and emits a signed replayable artifact.

## PFC Authority Flip Demo

- Agent requests $12.4M exposure
- Policy limit is $500K
- Execution authority is revoked (trade blocked)
- Signed decision artifact is produced (Ed25519)
- Replay verification recomputes hashes + verifies signature (PASS)

This demonstrates enforceable interruption — not advisory logging.

## Security Properties Demonstrated

- Deterministic decision hashing from stable JSON (`sort_keys=True`, compact separators) and SHA-256.
- Ed25519 signature over UTF-8 bytes of `decision_hash`.
- Replay verifier recomputes hashes and checks signature integrity.

## Threat Model (Demo Scope)

This demo assumes:
- The runtime process/host is trusted
- The signing key is local to the demo runtime
- Policy and request inputs are well-formed JSON

Out of scope (production hardening):
- Host compromise or key exfiltration
- HSM/KMS-backed key custody
- Cross-language canonicalization equivalence

## Run in under a minute

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_demo.py
python verify_replay.py
python -m unittest
```

## Independent Verification

```bash
python verify_replay.py --artifact artifacts/decision_record.json --public-key keys/public_key.pem
```

Note: Verification requires the verifier to obtain and pin the expected public key (or fingerprint) from a trusted channel. The fingerprint identifies which key signed the record, not whether the key is trusted.

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
- signature verify (OK): OK
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

## 10,000 Stability Run

Implementation location: `pfc_scale/`.
Runtime outputs:
- `pfc_scale/ledger/` (JSONL ledgers, sqlite index, logs)
- `pfc_scale/keys/` (local dev keys only)
- `/tmp/pfc_sandbox/` (execution sandbox)

### 1. Start Redis

Supported real-Redis options on macOS:

`A) Homebrew (preferred on this machine)`

```bash
brew install redis
brew services start redis
redis-cli ping
```

`B) Docker (optional, only if Docker Desktop works)`

```bash
docker run -d --rm -p 6379:6379 --name pfc-redis redis:7
```

Redis reference: [Install Redis on macOS using Homebrew](https://redis.io/docs/latest/operate/oss_and_stack/install/archive/install-redis/install-redis-on-mac-os/).

### 2. Install deps

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r pfc_scale/requirements.txt
```

### 3. Start gate service

```bash
uvicorn pfc_scale.gate_service:app --host 127.0.0.1 --port 8000
```

### 4. Start worker

```bash
python3 -m pfc_scale.worker --redis-url redis://127.0.0.1:6379/0 --consumer-name worker-1 --run-id run-10000 --max-messages 10000
```

### 5. Enqueue 10,000 intents

```bash
python3 scripts/enqueue_10000_intents.py --redis-url redis://127.0.0.1:6379/0 --stream pfc:intents --count 10000
```

### 6. Run replay check

```bash
python3 scripts/replay_check.py --sample-size 200
python3 scripts/replay_check.py --run-id run-10000 --sample-size 200
```

Ledger files are cumulative across runs. Use `--run-id` for a per-run audit view with the same verification rules.

### 7. Fault injection

```bash
bash scripts/fault_injection_run.sh
```

## Crash Recovery Proof

Run deterministic crash/restart proof with real Redis only:

```bash
bash scripts/run_crash_recovery_10000.sh
```

This validates:
- worker crashes mid-run after terminal receipt write (`CRASH_INJECTED`)
- restart reclaims pending messages via consumer-group recovery
- no double execution (idempotency by `intent_id`)
- replay verification remains strict and clean (`mismatches=0`)
- no stuck pending messages (`XPENDING=0` at completion)

### Expected run summary format

```text
total_messages=10000
unique_intents=9900
receipts_written=10000
duplicate_messages=100
allowed_executed=X
denied=Y
malformed=Z
expired_blocked=M
mismatches=0
```

Execution idempotency is enforced by `intent_id`. Duplicate stream messages with the same `intent_id` do not execute twice and produce a signed `duplicate_ack` receipt linked to original decision evidence.
