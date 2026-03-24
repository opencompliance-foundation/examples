# Public Fixtures

This directory is the private source of truth for the first public export to `opencompliance-foundation/examples`.

Only public-safe synthetic fixtures belong here.

## Current fixture set

- `minimal/`
  A small example pack showing:
  - typed evidence claims,
  - raw synthetic source exports that generate those claims,
  - a proof bundle,
  - a trust-surface report,
  - a verification-result envelope,
  - a typed punch-list,
  - a replay bundle,
  - a witness receipt,
  - a revocation artifact,
  - and a seed OSCAL projection of the same bundle.
- `failed/`
  A narrow synthetic ExampleCo corridor showing:
  - present-but-failing machine evidence as a first-class result,
  - a typed punch-list that distinguishes failed from missing,
  - a replay bundle and witness receipt for a blocked run,
  - and a matching seed OSCAL projection.
- `medium/`
  A richer synthetic ExampleCo corridor showing:
  - multi-framework family mappings across ISO 27001, SOC 2, IRAP, and GDPR,
  - a wider set of typed machine and human claims,
  - explicit control references back into the synthetic OpenCompliance corridor catalog,
  - a blocked Verify path with a typed punch-list and replay bundle,
  - and a larger OSCAL-shaped projection that stays public-safe.
- `issued/`
  A narrow certificate-eligible ExampleCo corridor showing:
  - deterministic success-path verification,
  - raw synthetic source exports that generate the covered claims,
  - a scoped certificate artifact,
  - a replay bundle suitable for exact-match witness reruns,
  - and the same public-safe OSCAL projection style as the other packs.
- `stale/`
  A narrow freshness-blocked ExampleCo corridor showing:
  - present-but-expired machine and human evidence,
  - a typed punch-list that distinguishes stale evidence from failed predicates or missing claims,
  - a replay bundle and witness receipt for a blocked run,
  - and the same public-safe OSCAL projection style as the issued corridor.
