# OpenCompliance Evidence Schema

This directory is the private source of truth for the public export to `opencompliance-foundation/evidence-schema`.

The first release publishes a draft envelope for typed evidence claims and a small set of claim-type payload schemas aligned to the public synthetic examples.

## Current contents

- `STATUS.md`
- `schemas/evidence-claim.schema.json`
- `schemas/claim-types/*.schema.json`
- `examples/evidence-claim.example.json`

## Current notes

- The schema set now covers the current synthetic claim types used by the minimal, failed, medium, stale, issued, cyber-baseline, and AI-governance ExampleCo corridors, including repo-policy and CI-policy connector examples, typed password-policy, managed-WAF, centralized-monitoring, storage-encryption, infrastructure-identity-uniqueness, and environment-segmentation exports for the newer decidable corridor slices, change-review, access-review-closure, monitoring-review, vendor-terms, and incident-governance attestations in the medium or issued packs, freshness-downgraded evidence in the stale pack, Cyber Essentials-style cyber hygiene exports, and AI-governance attestations plus AI disclosure state.
- The schema set also now includes candidate claim types for future expansions beyond the current public corridors, including configuration and patch exception attestations, vendor or patch adequacy-boundary support artifacts, and the next AI-assurance layer for provenance metadata, structured evaluation records, and data-quality governance attestations.
- The actor ontology and deterministic rejection rules live in the private runtime and docs until the public schema registry grows beyond the seed corridor.
