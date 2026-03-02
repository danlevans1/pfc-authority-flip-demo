# Incident Replay One-Pager

## Decision Summary and Proof Pointers
This decision record proves that a specific policy (`demo-finance-exposure-v1`) and a specific request were evaluated deterministically, resulting in a denied action (`AUTHORITY_REVOKED`), with a signed artifact that can be independently re-verified.

Proof pointers (exact fields):
- Policy identity: `$.decision_core.policy_id` (and source policy file `policy.json` at `$.policy_id`).
- Policy hash: `$.decision_core.policy_hash` (deterministic hash of `policy.json`).
- Request identity/hash: `$.decision_core.request_hash` (deterministic hash of `agent_request.json`), with request actor at `agent_request.json` path `$.agent_id`.
- Allow or deny decision: `$.decision_core.event` (`ALLOW` or `AUTHORITY_REVOKED`).
- Authority state (revoked or allowed): `$.decision_core.event` (this run is `AUTHORITY_REVOKED`) and `$.decision_core.reason`.
- Signature verification result: artifact contains signature material at `$.signature`, `$.signature_alg`, and `$.public_key_fingerprint`; `verify_replay.py` returns exit code `0` on successful verification and nonzero on failure.

Canonical proof tie-out: `$.decision_core.event` + `$.decision_core.policy_hash` + `$.decision_core.request_hash` + (`$.signature`, `$.signature_alg`, `$.public_key_fingerprint`) are sufficient to bind the decision to the hashed inputs and signature material.

Quick Proof (read key fields directly):
```bash
# From repo root:
set -euo pipefail

shasum -a 256 -c pfc_incident_replay.sha256
TMP_DIR="$(mktemp -d /tmp/pfc_replay.XXXXXX)"
unzip -q pfc_incident_replay.zip -d "$TMP_DIR"
RUN_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'run_*' | head -n 1)"
ls -1 "$RUN_DIR"/decision_record.json "$RUN_DIR"/policy.json "$RUN_DIR"/agent_request.json "$RUN_DIR"/public_key.pem "$RUN_DIR"/verify_replay.py

python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("policy_id:", d["decision_core"]["policy_id"]); print("policy_hash:", d["decision_core"]["policy_hash"]); print("request_hash:", d["decision_core"]["request_hash"]); print("event:", d["decision_core"]["event"]); print("reason:", d["decision_core"]["reason"])' \
  "$RUN_DIR/decision_record.json"

python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); r=json.load(open(sys.argv[2])); print("policy.policy_id:", p.get("policy_id")); print("request.agent_id:", r.get("agent_id")); print("request.action:", r.get("action")); print("request.requested_exposure_usd:", r.get("requested_exposure_usd"))' \
  "$RUN_DIR/policy.json" "$RUN_DIR/agent_request.json"

python3 "$RUN_DIR/verify_replay.py" --policy "$RUN_DIR/policy.json" --request "$RUN_DIR/agent_request.json" --artifact "$RUN_DIR/decision_record.json" --public-key "$RUN_DIR/public_key.pem"

# Optional cleanup (safe: /tmp only)
rm -rf -- "$TMP_DIR"
```

## A) What happened (plain language)
A simulated agent requested a trade with **$12,400,000** exposure while the policy limit allowed only **$500,000**. The policy engine deterministically revoked execution authority, blocked the trade, and produced a signed decision record. Replay verification then recomputed hashes from the same inputs and verified the Ed25519 signature, resulting in **PASS**.

## B) What is inside the bundle
The replay zip contains one run directory:
- `decision_record.json`: signed authority decision artifact (decision core, deterministic decision hash, signature, key fingerprint, timestamp).
- `policy.json`: policy input used for the decision.
- `agent_request.json`: canonical request input used for the decision.
- `public_key.pem`: public key used to verify the signature.
- `run_demo.py`: demo runner used to generate the artifact.
- `verify_replay.py`: verifier used to independently replay/verify the artifact.
- `run_demo.log`: captured output from the authority flip run.
- `verify_replay.log`: captured output from explicit replay verification.
- `DEMO_SCRIPT.md`, `README.md`: replay instructions and repo documentation included with the run package.

## C) Exact verification steps
From a clean directory:

```bash
# 1) Verify checksum
shasum -a 256 -c pfc_incident_replay.sha256

# 2) Unpack
unzip pfc_incident_replay.zip

# 3) Identify extracted run dir (example shown)
RUN_DIR="run_20260302T032316Z"

# 4) Replay verification from extracted bundle inputs
python3 "$RUN_DIR/verify_replay.py" \
  --policy "$RUN_DIR/policy.json" \
  --request "$RUN_DIR/agent_request.json" \
  --artifact "$RUN_DIR/decision_record.json" \
  --public-key "$RUN_DIR/public_key.pem"
```

`verify_replay.py` recomputes canonicalized hash inputs (`policy_hash`, `request_hash`, `decision_hash`) and verifies the Ed25519 signature over the deterministic decision hash.

`verify_replay.py` prints replay verification status lines and returns success exit code (`0`) on valid replay (nonzero on failure).

## Tamper Tests (Expected Failures)
These tests show verification fails if the policy, request, or decision record are modified.

```bash
# Safe prep (repo root)
set -euo pipefail
shasum -a 256 -c pfc_incident_replay.sha256
TMP_DIR="$(mktemp -d /tmp/pfc_replay_tamper.XXXXXX)"
unzip -q pfc_incident_replay.zip -d "$TMP_DIR"
RUN_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'run_*' | head -n 1)"
test -d "$RUN_DIR"
ls -1 "$RUN_DIR"/decision_record.json "$RUN_DIR"/policy.json "$RUN_DIR"/agent_request.json "$RUN_DIR"/public_key.pem
```

Test A (policy tamper): EXPECTED FAIL
```bash
python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["tamper_test"]="policy_changed"; json.dump(d, open(p, "w"), indent=2)' \
  "$RUN_DIR/policy.json"
set +e
python3 "$RUN_DIR/verify_replay.py" --policy "$RUN_DIR/policy.json" --request "$RUN_DIR/agent_request.json" --artifact "$RUN_DIR/decision_record.json" --public-key "$RUN_DIR/public_key.pem"
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
  echo "EXPECTED FAIL: policy tamper rejected"
else
  echo "UNEXPECTED PASS: policy tamper was not detected"
fi
```

Test B (decision record tamper): EXPECTED FAIL
```bash
python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["decision_core"]["reason"]="tampered reason"; json.dump(d, open(p, "w"), indent=2)' \
  "$RUN_DIR/decision_record.json"
set +e
python3 "$RUN_DIR/verify_replay.py" --policy "$RUN_DIR/policy.json" --request "$RUN_DIR/agent_request.json" --artifact "$RUN_DIR/decision_record.json" --public-key "$RUN_DIR/public_key.pem"
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
  echo "EXPECTED FAIL: decision record tamper rejected"
else
  echo "UNEXPECTED PASS: decision record tamper was not detected"
fi
```

Test C (request tamper): EXPECTED FAIL
```bash
python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["requested_exposure_usd"]=d.get("requested_exposure_usd",0)+1; json.dump(d, open(p, "w"), indent=2)' \
  "$RUN_DIR/agent_request.json"
set +e
python3 "$RUN_DIR/verify_replay.py" --policy "$RUN_DIR/policy.json" --request "$RUN_DIR/agent_request.json" --artifact "$RUN_DIR/decision_record.json" --public-key "$RUN_DIR/public_key.pem"
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
  echo "EXPECTED FAIL: request tamper rejected"
else
  echo "UNEXPECTED PASS: request tamper was not detected"
fi
```

```bash
# Cleanup (/tmp only)
rm -rf -- "$TMP_DIR"
```
