# U.S. Sector Review Program

This file defines the reviewer roles, tracks, and phases for the first U.S. sector-regime depth wave.

## Review tracks

- `health-privacy-law`: Challenge HIPAA privacy and breach mappings against real regulated-health workflow expectations.
  - Required roles: `health_privacy_counsel`, `regulated_health_operator`
- `financial-regulation`: Challenge GLBA and NYDFS overlap claims against financial-sector security and governance expectations.
  - Required roles: `financial_regulation_counsel`, `fintech_security_operator`
- `consumer-privacy-law`: Challenge CCPA/CPRA rights, retention, and service-provider mappings against California privacy-law practice.
  - Required roles: `consumer_privacy_counsel`, `privacy_engineer`
- `control-engineering`: Challenge whether the mapped controls are actually narrow enough to be trustworthy and testable.
  - Required roles: `security_engineer`, `formal_methods_reviewer`

## Phases

- `phase_1_anchor_review`: Confirm that published exact anchors and relation semantics are defensible.
  - Each published anchor has an authoritative public source and a narrow relation statement.
  - No documented objection says a published exact anchor overclaims the current control.
- `phase_2_control_boundary_review`: Confirm that the mapped public controls are narrow enough to support proof, attestation, or judgment routing.
  - Each reviewed control has an explicit route and a credible evidence story.
  - No reviewed control silently hides a rights-heavy or judgment-heavy obligation behind a proof-like label.
- `phase_3_fixture_and_output_review`: Confirm that fixture-backed public examples tell the truth about what is and is not shown.
  - Trust-surface reports do not imply full HIPAA, GLBA, NYDFS, or CCPA compliance from narrow example corridors.
  - Remaining gaps and judgment layers are visible to external readers.

