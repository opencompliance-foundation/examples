# ExampleCo Medium Trust-Surface Report

**Bundle:** `exampleco-medium-bundle-2026-03-24`  
**Profile:** `medium_multiframework_corridor`

## Executive Summary

This synthetic example shows a wider OpenCompliance corridor without pretending the corridor is complete:

- `6` proved claims
- `4` attested claims
- `0` failed claims
- `1` judgment-required claim
- `1` evidence-missing claim

## Proved

- Administrative identities require MFA and conditional access in the scoped production environment.
- Audit logging is enabled with a declared retention window for the scoped production runtime.
- Public ingress is HTTPS-only with managed certificates and TLS 1.2 or higher.
- Scoped runtime service accounts do not use user-managed long-lived keys.
- The scoped workload runs only in the declared approved regions.
- Backup snapshots are scheduled with a declared immutable retention window.

## Attested

- Security awareness completion is documented for the current review period.
- A restore exercise is documented inside the declared review window.
- The processor register is current and DPA coverage is declared for the reviewed subprocessors.
- The DSR runbook is approved and has a named owner for the current review window.

## Failed


## Judgment Required

- Privacy-by-design adequacy has been demonstrated for the full product change process.

## Evidence Missing

- A typed export of periodic access review evidence is present for the current review window.

## Why This Example Exists

It is public-safe and synthetic, but it demonstrates a more serious corridor than the minimal pack:

- multi-framework family mappings,
- explicit control references back into the synthetic OpenCompliance catalog,
- a cleaner split between runtime proofs and signed attestations,
- and a still-honest boundary where legal or adequacy judgment remains human.
