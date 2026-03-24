# Failed Public Example

This example is synthetic.

It exists to show a present-but-failing claim as data instead of a verifier crash.

## Files

- `profile.json`
- `source-exports/`
- `evidence-claims.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `punch-list.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `oscal/`

## Intended use

- inspect how the verifier encodes a failed machine-state claim,
- compare failed versus missing-evidence blocking issues,
- confirm that only proved claims enter the Lean batch,
- and validate that the punch-list stays typed when evidence is present but bad.

## Boundary

This pack is intentionally narrow and synthetic.

It is not a production negative-test matrix.
