# Release Notes

## v0.1.3 (unreleased)

### Summary

- README verification command corrected to match `verify_replay.py` CLI flags.
- Verifier output now includes explicit signature reason codes.

### Security/integrity highlights

- Fail-closed enforcement defaults to deny when `enforcement` is missing.
- Public key fingerprint is SHA-256 over raw Ed25519 public key bytes.
- `decision_hash` is deterministic SHA-256 over canonical `decision_core`.
- Signature is Ed25519 over UTF-8 bytes of `decision_hash`.

### Dependencies

- Runtime dependency remains `cryptography` via `requirements.txt`.

## v0.1.0

### Summary

- Initial public demo for deterministic execution authority revocation.
- Signed, replayable decision records with Ed25519 verification.
- Local-first workflow with online and offline install paths.

### Included

- Demo runner (`run_demo.py`) for the blocked trade scenario.
- Signed decision artifact generation (`artifacts/decision_record.json`).
- Replay verifier (`verify_replay.py`) with per-check PASS/FAIL output.
- Air-gapped/offline installation instructions in README.
- GitHub Actions CI workflow for tests, demo run, and replay verification.

### Compatibility

- Python 3.10 to 3.13.
- Requires `cryptography` from `requirements.txt`.

### Integrity notes

- `decision_hash` is deterministic and excludes timestamps.
- Signature is over UTF-8 bytes of `decision_hash`.
