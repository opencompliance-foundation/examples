# Proprietary Framework Publication Model

This file records how OpenCompliance treats proprietary or licensed standards such as ISO 27001 and SOC 2.

The goal is to publish as much derived mapping metadata as possible without bluffing about exact anchors or reproducing non-public source text.

## Publication tiers

### Public structural metadata

- framework priority and source-availability state
- framework coverage counts
- control-family mappings
- review blocker records
- public-control route and fixture status

### Public derived mapping metadata

- publication-safe control IDs
- relation semantics such as subset-of or intersects-with
- mapping-method metadata
- review status and confidence
- family-by-family rollout matrices

### Private exact-anchor corpus

- licensed clause, Annex A, criterion, and point-of-focus anchors
- private source-to-atom mapping graph
- reviewer notes that quote or paraphrase licensed text beyond public-safe limits

### Licensed review outputs

- blocker resolutions
- review sign-off state
- private evidence that a public exact-anchor publication is defensible

## Framework policies

### ISO 27001

- Source availability: `blocked_nonpublic_source_review`
- Public allowed:
  - structural clause-versus-Annex-A state
  - family-level mappings
  - control-boundary metadata
  - blocker-aware exact-anchor status
- Private allowed:
  - exact clause and Annex A review
  - private source-to-atom graph
  - licensed review notes
- Public blocked:
  - open publication of a full exact-anchor corpus without licensed review
  - verbatim or near-verbatim reproduction of proprietary standard text

### SOC 2

- Source availability: `blocked_nonpublic_source_review`
- Public allowed:
  - criterion-family and point-of-focus group state
  - public-control mappings
  - blocker-aware exact-anchor status
- Private allowed:
  - exact criterion and point-of-focus review
  - private source-to-atom graph
  - licensed review notes
- Public blocked:
  - open publication of a full exact-anchor corpus without licensed review
  - verbatim or near-verbatim reproduction of proprietary standard text

### ISO/IEC 27701

- Source availability: `blocked_nonpublic_source_review`
- Public allowed:
  - priority state
  - family-level mappings
  - candidate control coverage
- Private allowed:
  - licensed clause review
  - private source-to-atom graph
- Public blocked:
  - public exact-anchor corpus until licensed review exists

### ISO/IEC 42001

- Source availability: `crosswalk_candidate_requires_licensed_review`
- Public allowed:
  - crosswalk-derived candidate anchors
  - public blocker metadata
  - candidate control coverage
- Private allowed:
  - licensed clause review
  - private exact-anchor notes
- Public blocked:
  - claiming public reviewed exact anchors from crosswalk material alone

