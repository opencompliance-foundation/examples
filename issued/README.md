# Issued Public Example

This example is synthetic.

It exists to show the narrow certificate path for OpenCompliance without leaking any private customer, deployment, or audit material.

## Files

- `profile.json`
- `source-exports/`
- `evidence-claims.json`
- `classification-result.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `certificate.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `transparency-log.json`
- `inclusion-proofs.json`
- `oscal/`

## What is different from the other packs

- the corridor is intentionally narrower than `../medium/`,
- every in-scope control has either machine evidence or signed attestation,
- typed access-review exports and signed closure attestations now appear together in the same issued pack,
- the pack now also carries a narrow proved storage-encryption slice instead of leaving encryption-at-rest as prose only,
- the pack also includes a signed incident-runbook attestation without pretending to prove the whole incident program,
- there are no judgment-required or missing-evidence blockers,
- and the deterministic Verify surface therefore issues a synthetic certificate artifact instead of a punch-list.

## Intended use

- test the successful Verify path,
- inspect a raw-to-typed evidence conversion path,
- review a narrow certificate artifact without over-claiming whole-framework coverage,
- exercise replay-bundle and witness-receipt generation for a certificate-eligible run,
- and keep the public examples honest about what a scoped certificate means.
