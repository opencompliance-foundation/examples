# Medium Public Example

This example is synthetic.

It exists to show a richer public-safe corridor than `../minimal/` without leaking customer or internal deployment material.

## Files

- `company.json`
- `profile.json`
- `evidence-claims.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `witness-receipt.json`
- `revocation.json`
- `oscal/`

## What is different from the minimal pack

- four-framework family mappings across ISO 27001, SOC 2, IRAP, and GDPR,
- more typed machine claims,
- more typed human attestations,
- explicit `controlRefs` back into the synthetic OpenCompliance corridor catalog,
- and a wider OSCAL-shaped projection.

## Intended use

- test multi-framework import and export logic,
- exercise richer schema payloads,
- validate a larger witness receipt,
- and review how OpenCompliance keeps proofs, attestations, judgment, and missing evidence separate in a more realistic synthetic corridor.
