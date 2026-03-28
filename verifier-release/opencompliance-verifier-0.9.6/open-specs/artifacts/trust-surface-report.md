# Trust-Surface Report

## Purpose

A trust-surface report is the human-readable explanation of what a verification result rests on.

It must not flatten different epistemic categories into one status.

## Required content

1. Bundle identifier.
2. Verification profile or scope identifier.
3. Summary counts for:
   - `proved`
   - `attested`
   - `failed`
   - `stale_evidence`
   - `judgment_required`
   - `evidence_missing`
4. Scope statement.
5. High-value claims in each category.
6. Explicit next evidence or formalization gaps.

## Required semantics

- `proved` means derived from deterministic system state or equally deterministic typed input.
- `attested` means supported by signed or documentary evidence but not mechanically proved.
- `failed` means the required claim was present but did not satisfy the corridor predicate.
- `stale_evidence` means the required claim was present but had expired before the verification run.
- `judgment_required` means a human reviewer or auditor still has to decide adequacy or interpretation.
- `evidence_missing` means the claim is a candidate for proof or attestation but the required input is absent.

## Output discipline

- The report must say what remains unresolved.
- The report must not imply that judgment-heavy controls were machine-proved.
- If a certificate is withheld, the report should still be publishable as a typed punch-list.
