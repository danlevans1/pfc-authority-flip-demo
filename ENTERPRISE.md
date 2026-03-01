# Enterprise Notes

## What this demo proves

- Deterministic authority boundary enforcement: requests above policy limit are denied.
- A signed decision artifact is produced at the authority boundary event.
- Replay verification recomputes policy, request, and decision hashes and verifies the signature.
- Runtime execution has no network dependency.

## What this demo does NOT claim

- It is not a full production authorization system.
- It does not provide secure production key storage (no HSM or KMS integration).
- It does not provide tamper-proof filesystem guarantees.
- It is not a complete policy language implementation (no rich RBAC/ABAC model).
- It is not a full agent runtime or sandbox.
- It does not provide identity federation, SSO, or enterprise IAM integration.
- It is not, by itself, a compliance certification artifact.

## Threat model

- The replay check is intended to detect decision-record tampering when policy, request, artifact, and trusted public key are preserved.
- If an attacker can modify both the artifact and verifier inputs without an independent trust anchor, integrity cannot be guaranteed.
- If an attacker controls the machine and replaces both artifact and public key, verification can be subverted.
- Keys in this repo are local demo keys. For production, use HSM/KMS-backed keys, attestation, and append-only logs.

## Mapping to real deployment

- Placement: use this as an execution gate in front of real actuation (trade submits, data exports, privileged API calls).
- Inputs: policy artifact plus normalized request payload.
- Outputs: allow/deny decision plus signed decision record.
- Typical hardening path: managed key lifecycle, append-only decision logs, remote attestation, policy distribution controls, and optional multi-signature approvals.

## Contact / next step

If you want this wrapped around your workflow as a 30-day Authority Exposure Diagnostic, contact: Dan Evans
