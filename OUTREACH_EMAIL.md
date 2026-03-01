# Outreach Email Templates

## 1) CTO / Platform Lead

Subject: Deterministic execution authority demo (signed + replayable)

Hi {{FirstName}},

I published a minimal demo that enforces an execution boundary, emits a signed decision record, and verifies replay integrity locally: https://github.com/danlevans1/pfc-authority-flip-demo/releases/tag/v0.1.0
You can run it in minutes and independently verify deterministic policy/request hashes plus Ed25519 signature validation over `decision_hash` bytes.

Open to a 20-minute call for a 30-day pilot where we instrument one workflow and produce replayable decision records?

## 2) Risk / Compliance

Subject: Replayable decision records for execution controls (demo)

Hi {{FirstName}},

I put together a small public demo showing a policy violation that deterministically blocks execution, writes a signed artifact, and supports replay verification: https://github.com/danlevans1/pfc-authority-flip-demo/releases/tag/v0.1.0
Your team can run it locally and verify that the decision inputs, hashes, and signature checks are reproducible without external services.

Open to a 20-minute call for a 30-day pilot where we instrument one workflow and produce replayable decision records?
