# GDPR and AI Publication Model

This file records how OpenCompliance treats GDPR and the current ISO AI standards wave when publishing mapping metadata.

## GDPR

- Source availability: `public_exact_feasible`
- Public allowed:
  - article-level and obligation-level exact anchors
  - public-control mappings
  - typed claim contracts
  - reviewed public-law rationale
- Private allowed:
  - working notes and reviewer drafts
  - internal decomposition scratch space
- Public blocked:
  - claiming mechanised or proved coverage for judgment-heavy obligations without explicit boundary notes

## ISO/IEC 42001

- Source availability: `crosswalk_candidate`
- Public allowed:
  - crosswalk-derived candidate anchors
  - public-control coverage counts
  - candidate review metadata
- Private allowed:
  - licensed clause review
  - private exact-anchor notes
- Public blocked:
  - claiming reviewed exact anchors from public crosswalk material alone

## ISO/IEC 42005

- Source availability: `crosswalk_candidate`
- Public allowed:
  - crosswalk-derived candidate anchors
  - impact-assessment-oriented control mappings
  - candidate review metadata
- Private allowed:
  - licensed clause review
  - private impact-assessment anchor notes
- Public blocked:
  - claiming reviewed exact anchors from public crosswalk material alone

## ISO/IEC 5338

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate lifecycle-process mappings
  - public control and fixture coverage counts
- Private allowed:
  - licensed clause review
  - private lifecycle-process notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC 23894

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate risk-management mappings
  - candidate review metadata
- Private allowed:
  - licensed clause review
  - private risk-management review notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC 5259-5

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate data-quality-governance mappings
  - public control coverage counts
- Private allowed:
  - licensed clause review
  - private data-quality notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC TS 6254

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate explainability-oriented mappings
  - framework inventory and maturity state
- Private allowed:
  - licensed clause review
  - private explainability notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC 22989

- Source availability: `crosswalk_candidate`
- Public allowed:
  - framework inventory and terminology-support state
  - ontology support notes
- Private allowed:
  - licensed terminology review
  - private ontology notes
- Public blocked:
  - presenting terminology support as a reviewed control-mapping layer

## ISO/IEC 23053

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate ML-systems-framework mappings
  - public inventory and maturity state
- Private allowed:
  - licensed clause review
  - private engineering-framework notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC 38507

- Source availability: `crosswalk_candidate`
- Public allowed:
  - candidate governance-role mappings
  - public inventory and maturity state
- Private allowed:
  - licensed clause review
  - private governance notes
- Public blocked:
  - exact clause publication without licensed review

## ISO/IEC 42006

- Source availability: `crosswalk_candidate`
- Public allowed:
  - ecosystem inventory and certification-layer notes
- Private allowed:
  - licensed clause review
  - private certification-process notes
- Public blocked:
  - presenting certification-body requirements as current operator control coverage

## ISO/IEC AWI 42003

- Source availability: `public_draft`
- Public allowed:
  - draft-watch inventory
  - maturity-state notes
- Private allowed:
  - draft-monitoring notes
- Public blocked:
  - treating a draft guidance project as a stable exact-anchor target

