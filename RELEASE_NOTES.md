# Release Notes

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
