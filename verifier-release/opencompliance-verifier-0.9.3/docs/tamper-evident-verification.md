# Tamper-Evident Verification

## Current prototype

The private reference runtime now includes:

- canonical JSON digests for machine-readable artifacts,
- a Merkle-style append-only transparency log prototype,
- inclusion proofs for each logged artifact,
- and verification scripts for the generated log.

## Current logged artifact set

The transparency prototype now covers:

- `profile.json`
- `evidence-claims.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `certificate.json` or `punch-list.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`

## Current limitation

The remaining hard gap is identity-bound signing and a public release process for the logged artifacts.

The current prototype makes mutation detectable inside the synthetic corridor, but it is not yet a full public signing plane.
