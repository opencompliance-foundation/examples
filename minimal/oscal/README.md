# Minimal OSCAL Seed Fixtures

These files show how the synthetic `ExampleCo` bundle can be projected into an OSCAL-shaped artifact set.

They are intentionally conservative.

- They use OSCAL model roots where possible: `catalog`, `profile`, `system-security-plan`, `assessment-plan`, `assessment-results`, and `mapping-collection`.
- They do not reproduce ISO 27001 or SOC 2 control text.
- The crosswalk to ISO 27001 and SOC 2 is family-level only, using proxy target identifiers.

## Files

- `opencompliance-minimal-catalog.json`
  Synthetic OpenCompliance corridor catalog with four narrow controls.
- `exampleco-minimal-profile.json`
  Scoped profile selecting the four controls used by the public example bundle.
- `exampleco-minimal-ssp.json`
  Synthetic system security plan for the ExampleCo corridor.
- `exampleco-minimal-assessment-plan.json`
  Example assessment plan for the same corridor.
- `exampleco-minimal-assessment-results.json`
  Assessment-results style output reflecting the public proof bundle.
- `family-proxy-targets.json`
  Proxy target identifiers for family-level ISO 27001 and SOC 2 overlap mapping.
- `iso27001-soc2-family-overlap-mapping.json`
  OSCAL control-mapping model seed using the family proxy targets.

## Interpretation rule

This folder demonstrates how OpenCompliance can align its internal example artifacts with OSCAL document shapes.

It does not claim that the ISO 27001 and SOC 2 mappings here are clause-level, audit-ready, or complete.
