# Evidence Corridor

## Current synthetic connector scope

The current file-based connector corridor is intentionally narrow.

It generates typed evidence claims from raw synthetic source exports for:

- repo branch-protection policy,
- CI workflow policy,
- IAM / MFA state
- cloud logging state
- edge TLS configuration
- machine credential hygiene
- region inventory
- backup scheduling
- HR training attestations
- restore-test attestations
- vendor-register attestations
- DSR runbook attestations

## Current fixtures

Today the generated source-export path covers:

- `fixtures/public/minimal/`
- `fixtures/public/failed/`
- `fixtures/public/medium/`
- `fixtures/public/stale/`
- `fixtures/public/issued/`

## Why this still matters

This is enough to demonstrate a serious property:

raw source exports can be normalized into typed claims deterministically, then fed into the same Verify surface and replay flow.

The public stale corridor now also shows that freshness expiry is enforced as data: present-but-expired evidence is downgraded into a typed blocker instead of being silently treated as current.

## Current limitation

This is not yet the live connector layer described in the PRD.

The remaining missing pieces are:

- live auth flows,
- and a broader live connector matrix beyond the current synthetic file-based path.
