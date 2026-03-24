# Medium OSCAL Seed Fixtures

These files show how the richer synthetic `ExampleCo` bundle can be projected into an OSCAL-shaped artifact set.

They are still conservative.

- They use OSCAL model roots where possible: `catalog`, `profile`, `system-security-plan`, `assessment-plan`, `assessment-results`, and `mapping-collection`.
- They do not reproduce ISO 27001, SOC 2, IRAP, or GDPR text.
- The crosswalks stay at the family level using synthetic proxy target identifiers.

## Files

- `opencompliance-medium-catalog.json`
  Synthetic OpenCompliance corridor catalog with twelve narrow controls.
- `exampleco-medium-profile.json`
  Scoped profile selecting the twelve controls used by the public medium bundle.
- `exampleco-medium-ssp.json`
  Synthetic system security plan for the ExampleCo medium corridor.
- `exampleco-medium-assessment-plan.json`
  Example assessment plan for the same corridor.
- `exampleco-medium-assessment-results.json`
  Assessment-results style output reflecting the public proof bundle.
- `family-proxy-targets.json`
  Proxy target identifiers for family-level ISO 27001, SOC 2, IRAP, and GDPR overlap mapping.
- `iso27001-soc2-irap-gdpr-family-overlap-mapping.json`
  OSCAL control-mapping model seed using the family proxy targets.

## Interpretation rule

This folder demonstrates how OpenCompliance can align a richer internal example set with OSCAL document shapes.

It does not claim clause-level, article-level, or audit-ready mappings for any framework named here.
