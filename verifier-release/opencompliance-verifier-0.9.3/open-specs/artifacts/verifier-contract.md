# Verifier Contract

`verifier-contract.json` is the machine-readable statement of what the current public verifier release guarantees.

It is narrower than the full product vision. The contract is only for the current synthetic public release line, not for arbitrary live-organisation evidence.

## What It Pins

- The release id and verifier version.
- The supported public fixture roots.
- The canonical entrypoint scripts shipped in the release.
- The required release-level artifacts such as `release-manifest.json`, `release-attestation.json`, `signed-artifact-manifest.json`, `public-key.pem`, and `open-specs/verifier-contract.json`.
- The bundled trust registries under `open-specs/actor-trust-policies.json` and `open-specs/actor-identities.json`, including the pinned synthetic signer key ids used by the current release line.
- The required per-fixture artifacts such as `proof-bundle.json`, `verification-result.json`, `replay-bundle.json`, `transparency-log.json`, `inclusion-proofs.json`, `witness-receipt.json`, `trust-surface-report.md`, and the OSCAL assessment-results projection.
- The issued-vs-punch-list outcome policy.
- The typed-boundary vocabulary expected from the proof runner and LegalLean-backed runtime layer.

## Why It Exists

Without a contract, the public runtime surface is only implied by the current example files.

With a contract, external users can tell:

- which files are part of the stable verifier surface,
- which artifact schemas define those files,
- which verification outcomes require which output artifacts,
- and which typed-boundary flags and module names are expected to stay stable across the current release line.

## What It Does Not Claim

- It does not claim live-connector support.
- It does not claim real-organisation evidence ingestion.
- It does not freeze the whole future product surface.
- It does not replace the individual artifact schemas; it ties them together into one release-level contract.
