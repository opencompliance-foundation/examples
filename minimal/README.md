# Minimal Public Example

This example is synthetic.

It exists to make the artifact model concrete without exposing customer evidence.

## Files

- `profile.json`
- `source-exports/`
- `evidence-claims.json`
- `classification-result.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `punch-list.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `transparency-log.json`
- `inclusion-proofs.json`
- `oscal/`

## Intended use

- review the format shape,
- inspect a raw-to-typed evidence conversion path,
- test import/export logic,
- inspect the blocked Verify path,
- derive basic conformance vectors,
- and show how the same synthetic company pack could be projected into OSCAL-shaped artifacts.

## Boundary

This minimal pack is intentionally small.

Use `../medium/` for the richer synthetic corridor that spans more frameworks, claim types, and OSCAL controls.
