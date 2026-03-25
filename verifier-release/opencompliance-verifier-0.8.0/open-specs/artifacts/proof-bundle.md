# Proof Bundle

## Purpose

A proof bundle is the machine-readable result of one verification run.

It is the artifact that later verification-result envelopes, punch-lists or certificates, signing, transparency logging, replay, and witness verification depend on.

## Minimum required fields

- `bundleId`
- `generatedAt`
- `verifierVersion`
- `organisation`
- `scope`
- `claims`
- `summary`
- `proofRunner`

## Claim object

Each claim entry should include:

- `claimId`
- `title`
- `result`
- `frameworkMappings`
- `controlRefs`
- `evidenceRefs`
- `basis`

## Allowed result values

- `proved`
- `attested`
- `failed`
- `stale_evidence`
- `judgment_required`
- `evidence_missing`

## Bundle rules

1. The same evidence package under the same verifier version should produce the same bundle content.
2. Evidence references must be stable identifiers, not opaque prose.
3. A proof bundle may be published without a certificate.
4. A proof bundle is replayable only if its required inputs are pinned or disclosed well enough for independent rerun.
5. A proof bundle does not by itself say whether a scoped certificate was issued or withheld. That decision belongs in the verification-result envelope.
6. If a claim is marked `proved`, the proof bundle should disclose which proof runner checked the decidable slice.

## Proof runner object

The `proofRunner` object should include:

- `batchId`
- `fixture` or equivalent scope identifier
- `status`
- `theoremCount`
- `verifiedTheorems`
- `importedModules`
- `verifiedClaims`
- `typedBoundaryLayer`
- `boundaryInventory`

Allowed status values:

- `verified`

`verifiedClaims` should say which proved claims actually entered the public Lean batch, which control boundary and predicate they used, and which theorem name was checked.

`typedBoundaryLayer` should expose the current typed legal-semantics surface when one exists. In the current public corridor that means the `LegalLean` dependency, the typed OpenCompliance modules that lift proof boundaries into `FormalisationBoundary`, the list of runtime-consumed claims when a corridor is already driven by Lean-side verdicts, and honest runtime flags indicating where typed control results, defeasibility, discretionary-term tagging, and the Python verdict replacement are actually live.

`boundaryInventory` should make the omission boundary explicit. If a claim is marked `proved` in the corridor but has no public Lean predicate yet, that omission belongs here instead of being silently hidden.

## Framework mapping entry

Each framework mapping entry should include:

- `framework`
- `family`
- optional `controlId`

These claim-level mappings are reduced projections for the verification artifact surface.

The authoritative mapping provenance for the current corridor lives in `control-boundaries.json` and the matching OSCAL mapping collections, where mapping maturity, target anchor plans, and proof boundaries can evolve without pretending the proof bundle alone is a reviewed standards crosswalk.

## Control reference rule

`controlRefs` should identify the narrow OpenCompliance corridor controls that the claim is asserting.

If a claim is intentionally outside the current formal corridor, `controlRefs` may be empty, but that should be a deliberate boundary choice rather than drift.

## Evidence-backed mapping rule

If a claim has `evidenceRefs`, the claim's `frameworkMappings` should match the union of the mapped evidence claims unless the mismatch is explicitly documented as a transformation or reduction step.
