# Continuous Verification

## Purpose

The first OpenCompliance verify loop is one-shot.

Continuous verification is the next layer: detect invalidating source changes, mark previously issued trust state as stale, and either revoke or require re-verification before composition can proceed.

## Current synthetic reference flow

1. Start from an issued narrow-corridor certificate plus its proof bundle.
2. Ingest a normalized source-change event that identifies impacted evidence refs and control refs.
3. Map the change to impacted proof claims.
4. Produce a lifecycle decision artifact:
   - `re_verification_required` when the certificate must be rerun before it can be trusted again, or
   - `revoked` when the policy is fail-closed.
5. Emit a delta-recheck plan that only targets impacted claims and explicitly lists reused claims.
6. Block higher-level composition until the impacted child certificate is reverified.

## Current private commands

Evaluate lifecycle drift:

```sh
cd projects/dev/opencompliance
python3 scripts/evaluate_lifecycle.py \
  --certificate fixtures/public/issued/certificate.json \
  --profile fixtures/public/issued/profile.json \
  --proof-bundle fixtures/public/issued/proof-bundle.json \
  --source-change fixtures/public/lifecycle/issued-source-change.json \
  --decision-policy revoke
```

Compose two issued component certificates:

```sh
cd projects/dev/opencompliance
python3 scripts/compose_certificates.py \
  --manifest fixtures/public/lifecycle/compose-manifest.json
```

## Current boundary

What exists today:

- A synthetic lifecycle decision artifact with impacted controls, impacted claims, lineage, and a delta-recheck plan.
- A synthetic component-certificate composition artifact for aligned issued children.
- Public-safe lifecycle example inputs and outputs under `fixtures/public/lifecycle/`.

What does not exist yet:

- No live source event stream.
- No certificate scheduler or background drift watcher.
- No automatic rerun pipeline after drift.
- No published signer identity for revocation or re-verification decisions.
