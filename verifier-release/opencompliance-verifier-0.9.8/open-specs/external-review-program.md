# External Review Program

This file records the external review and conformance path for the ISO 27001 and SOC 2 mapping wave.

## Review tracks

### exact_anchor_review

- Goal: Challenge the exact-anchor mapping edges and blocker decisions.
- Required roles: `iso_lead_auditor`, `soc2_assurance_practitioner`, `oscal_mapping_specialist`

### decomposition_review

- Goal: Challenge the source-to-atom decomposition and route assignment.
- Required roles: `iso_lead_auditor`, `soc2_assurance_practitioner`, `formal_methods_reviewer`

### claim_schema_review

- Goal: Challenge whether typed claim schemas match the intended evidence-bearing atoms.
- Required roles: `compliance_engineer`, `privacy_counsel`, `assurance_practitioner`

### lean_boundary_review

- Goal: Challenge which atoms are allowed into Lean and whether attestation and judgment boundaries are honest.
- Required roles: `formal_methods_reviewer`, `oscal_mapping_specialist`

### public_docs_review

- Goal: Challenge whether the public site overclaims what is proved or reviewed.
- Required roles: `privacy_counsel`, `assurance_practitioner`, `public_interest_reviewer`

## Review phases

### internal_preflight

- Goal: Ensure machine-readable status, publication model, and blocker inventory exist before requesting external time.
- Pass criterion: Framework coverage is current.
- Pass criterion: Exact-anchor blockers are explicit.
- Pass criterion: Source-to-atom graph status is recorded.

### licensed_anchor_review

- Goal: Review proprietary exact anchors privately where licensed material is required.
- Pass criterion: Anchor choices are challenged by a framework-qualified reviewer.
- Pass criterion: Public-vs-private publication decisions are recorded per anchor class.

### route_and_claim_review

- Goal: Review decomposition, route, and typed claim coverage before widening the public verifier surface.
- Pass criterion: Decidable atoms are explicitly distinguished from attestation and judgment atoms.
- Pass criterion: Typed claim contracts exist for promoted non-judgment atoms.

### public_release_review

- Goal: Check that the site and public repos do not overclaim the state of mapping or proof coverage.
- Pass criterion: Public wording stays blocker-aware.
- Pass criterion: No page implies certification or CPA opinion issuance by OpenCompliance.

