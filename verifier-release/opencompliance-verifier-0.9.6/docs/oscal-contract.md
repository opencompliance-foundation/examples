# OSCAL Contract

## Current scope

The current OSCAL bridge is deliberately narrow.

It supports the synthetic public ExampleCo corridors by ingesting:

- the OpenCompliance synthetic catalog,
- the matching OSCAL profile,
- the SSP implemented requirements,
- and the seed mapping-collection document.

## Current normalized representation

The bridge reduces the current OSCAL seed into normalized obligations with:

- `control_id`
- `title`
- `statement`
- `implementation_state`
- `mapping_targets`

This is enough for the current corridor to:

- reject dangling control references,
- reject missing mapping coverage,
- and emit a deterministic assessment-results style artifact from the proof bundle.

## Current boundary

The current OSCAL bridge does not yet claim:

- clause-complete ISO 27001 encoding,
- clause-complete SOC 2 encoding,
- full NIST OSCAL model coverage,
- a reviewed exact-anchor mapping layer for every public control,
- or a stable external interchange contract for arbitrary third-party packages.

It is a serious seed bridge for the current public corridor, not a complete OSCAL platform.

## Mapping interpretation

The current public mapping layer is still family-proxy.

That is deliberate. The Lean proofs attach to narrow OpenCompliance controls after decomposition, not to raw framework clauses or criteria. The next credible step is reviewed exact-anchor mapping for a small pilot set, not pretending the current corridor already encodes whole standards.

## Public-source advantage and blocker honesty

Some frameworks are much easier to review openly than others.

- Public official sources such as EUR-Lex and ACSC ISM guidance make it possible to publish a first exact-anchor pilot for selected GDPR and IRAP controls.
- Proprietary or account-gated standards such as ISO 27001 and SOC 2 require a stronger blocker discipline. OpenCompliance should publish those blockers explicitly rather than backfilling invented exact anchors from memory or secondary crosswalks.
