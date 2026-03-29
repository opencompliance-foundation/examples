# Public Synthetic Example Pack

## Purpose

A public synthetic example pack makes the OpenCompliance artifact model concrete without exposing private customer, vendor, or audit material.

It is the main safe publication unit for examples.

## Required files

- `profile.json`
- `evidence-claims.json`
- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`
- `transparency-log.json`
- `inclusion-proofs.json`

## Common optional files

- `company.json`
- `certificate.json`
- `classification-result.json`
- `punch-list.json`
- `system-description.json`
- `oscal/`

## Example-pack rules

1. Public example packs must be synthetic or explicitly cleared for publication.
2. Public example packs must not contain private customer data, partner data, production secrets, or internal-only architecture details.
3. Public example packs should state their synthetic nature plainly.
4. Public example packs should keep the native artifact set and the OSCAL projection internally consistent.
5. Public example packs should be usable for docs, schema review, conformance checks, and witness replay examples.

## Bundle linkage rule

Inside a serious example pack:

- evidence claims carry typed payloads and framework mappings,
- proof-bundle claims carry `frameworkMappings` and `controlRefs`,
- verification-result envelopes point to either a typed punch-list or a narrow certificate artifact,
- replay bundles pin the material input digests and expected output digests for reruns,
- witness receipts pin the digests for the proof bundle and its material replay inputs,
- transparency logs pin the canonical artifact digests into an append-ordered Merkle root,
- inclusion proofs let outsiders validate each logged artifact against that root,
- and the trust-surface report stays faithful to the bundle summary.

## Boundary note

An example pack is not a claim that the mapped frameworks are fully encoded, complete, or audit-ready.
