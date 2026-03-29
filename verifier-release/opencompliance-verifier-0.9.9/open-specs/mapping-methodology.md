# Mapping Methodology

## Current rule

OpenCompliance does not map raw framework clauses directly into Lean theorems.

The current public corridor works in three layers:

1. Source frameworks such as ISO 27001, SOC 2, IRAP, GDPR, Cyber Essentials, NIST CSF 2.0, NIST SP 800-53, and AI-governance sources like the EU AI Act or NIST AI RMF.
2. Narrow OpenCompliance controls that isolate a single atomic or near-atomic obligation.
3. Lean 4 predicates for the decidable slice of those OpenCompliance controls.

That is why the current public `control-boundaries.json` uses family-proxy mappings. The proofs attach to the OpenCompliance control layer, not to raw standards text.

## Optional private seed layer

There is one useful layer that can exist before the public OpenCompliance controls:

1. Framework-native source anchors.
2. Imported operational control inventories used only as a private seed layer.
3. Narrow OpenCompliance controls that isolate a single atomic or near-atomic obligation.
4. Lean 4 predicates for the decidable slice of those OpenCompliance controls.

The seed layer can be valuable because existing workflow tools often already cluster repeated framework anchors around reusable operational control nouns such as MFA, backup, vendor management, or secure development.

But that seed layer is not authoritative.

- Imported seed controls are often many-to-many with framework anchors.
- Imported seed controls often mix technical state, process evidence, and human judgment.
- Imported seed controls may carry source-specific naming, typos, or modeling quirks.

So OpenCompliance can use those inventories privately to accelerate decomposition, but it should only publish normalized OpenCompliance controls plus reviewed framework-native anchors.

## Why a direct clause-to-theorem model is wrong

Most real controls are mixed objects.

- Some parts are decidable from system state.
- Some parts require signed attestation.
- Some parts are irreducibly human judgment.

If the project tries to map an entire ISO 27001 clause or SOC 2 criterion to one theorem, it collapses those distinct epistemic categories and becomes misleading.

## Current state

The public corridor is still draft and family-proxy only.

- OpenCompliance controls are machine-readable and route-aware.
- Lean proofs exist for a narrow decidable subset.
- OSCAL-shaped mapping collections exist for the same synthetic corridor.
- Exact reviewed source anchors are not yet published for the public corridor.
- A private operational seed corpus can exist upstream of the public corridor, but it remains non-authoritative until decomposed and re-anchored to framework-native sources.
- The first private ISO 27001 / SOC 2 seed-decomposition pilot has already promoted access-review closure, password-policy, a managed-web-application-firewall slice, configuration exceptions, patch exceptions and adequacy boundaries, incident-procedure attestations, vendor-term and vendor-adequacy boundaries, and a narrow encryption-at-rest slice into public `oc.*` controls and synthetic ExampleCo corridors.
- That same pilot has now also promoted the network, transport, infrastructure-identity, segmentation, storage-confidentiality, and centralized-monitoring extensions `oc.net-02`, `oc.net-03`, `oc.net-04`, `oc.id-04`, `oc.seg-01`, `oc.crypt-01`, `oc.mon-01`, and `oc.mon-02`, so the next depth work is no longer "publish the pending wave" but "use the private ISO 27001 / SOC 2 framework-depth reports to choose the next availability, vulnerability-management, or deeper exact-anchor slice."

## State-of-the-art target

State of the art is a reviewed multi-layer mapping system:

1. Anchor every mapping to framework-native source identifiers.
   Examples: ISO clauses, Annex A controls, SOC 2 criteria, SOC 2 points of focus, IRAP/ISM controls, GDPR articles or other framework-native anchors.
2. Decompose each source requirement into atomic obligations before proof assignment.
3. Route each atomic obligation explicitly as `decidable`, `attestation`, `judgment`, or `mixed`.
4. Persist per-edge mapping metadata.
   Minimum fields: relation, mapping method, review status, and confidence.
5. Keep proof boundaries explicit.
   A Lean theorem proves only the decidable atom, not the whole source requirement by implication.
6. Publish coverage and non-coverage.
   Consumers must be able to see which source anchors are mapped, which are only partially covered, and which remain unresolved.
7. Export the result in OSCAL-native mapping artifacts at the right granularity.

## Practical interpretation for ISO 27001 and SOC 2

For ISO 27001 and SOC 2, the right pipeline is usually:

1. Start from the authoritative source requirement.
2. Decompose it into smaller obligations.
3. Bind each obligation to evidence types and route.
4. Formalize only the narrow decidable obligations in Lean 4.
5. Keep attestations and human judgments outside the proof kernel, but attached to the same obligation graph.

## Immediate next step

The next credible step is still not a fake "full mapping".

It is to keep upgrading the public corridor from family proxies toward reviewed source anchors with:

- explicit mapping maturity,
- exact-anchor plans per control,
- machine-checked mapping metadata,
- and a growing reviewed pilot set of clause- or criterion-grade mappings for a small number of controls at a time.

That first pilot now exists as a separate review artifact. It is intentionally mixed:

- public-source exact anchors where the authoritative source is actually open,
- candidate anchors where the public evidence is not yet strong enough,
- and explicit blocker entries where proprietary or non-public source material still prevents a defensible exact-anchor publication.

The same rule now applies to AI standards.

- Public EU and NIST AI frameworks can carry reviewed exact anchors.
- Public crosswalks into ISO AI standards can carry candidate anchors.
- Licensed ISO source review is still required before those candidate anchors can be promoted to reviewed exact-anchor status.
