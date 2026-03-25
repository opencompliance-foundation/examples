# Specs Status

## What exists today

- Draft format documents for the main public artifacts.
- Synthetic `ExampleCo` example bundles that follow those draft formats.
- A blocked Verify path via typed punch-lists, a first-class failed-claim path for present-but-bad evidence, a first-class stale-evidence path for expired claims, and a certificate path via the issued synthetic corridor.
- Replay-bundle artifacts that pin the public synthetic rerun inputs and expected outputs.
- Seed OSCAL projections for the same synthetic examples.
- Conformance vectors derived from the same examples.
- Draft linkage rules from proof-bundle claims into synthetic corridor control identifiers.
- A machine-readable control-boundary file for the current synthetic corridor.
- Explicit mapping-maturity metadata that says the current public corridor is still family-proxy and names the exact-anchor target state.
- A draft mapping-methodology note and a control-boundaries schema so mapping maturity and review intent are machine-checkable.
- A framework-source-availability note that separates public exact-anchor frameworks, crosswalk-derived candidates, and explicit blocker states.
- A first exact-anchor review pilot that now spans reviewed public-source anchors for GDPR, IRAP, Cyber Essentials, NCSC CAF 4.0, NIST CSF 2.0, NIST SP 800-53 Rev. 5.1, the EU AI Act, the EU GPAI Code of Practice, NIST AI RMF 1.0, the UK ICO AI and data protection guidance, the UK AI Cyber Security Code of Practice, the Australian Voluntary AI Safety Standard, NIST AI 600-1, NIST AI 100-4, NIST AI 700-2, ETSI EN 304 223, and ETSI TS 104 008.
- The same pilot now also records crosswalk-derived or abstract-derived candidate anchors for ISO/IEC 42001, ISO/IEC 23894, ISO/IEC 42005, ISO/IEC 5338, ISO/IEC 5259-5, and ISO/IEC AWI 25704 instead of pretending those ISO AI standards are already open-reviewed exact mappings.
- A public framework-priority list now records the actual depth order: ISO 27001, SOC 2, GDPR, IRAP, then the next AI-governance and AI-security standards relevant to legal-tech deployer style environments.
- A public framework-coverage report now joins that priority list with current control-boundary mappings and exact-anchor review state so others can see where the corridor is implemented, reviewed, blocked, or still only planned.
- Public synthetic corridors now exist for Cyber Essentials-style boundary/configuration/update/malware controls and for AI-governance controls spanning the EU AI Act, the EU GPAI Code of Practice, NIST AI RMF, and candidate ISO AI crosswalks.
- The AI-governance controls now also carry reviewed exact anchors into the UK ICO AI guidance layer, NIST AI 600-1, NIST AI 100-4, NIST AI 700-2, ETSI EN 304 223, and ETSI TS 104 008 where those frameworks fit the current narrow documentary or evaluation corridor, while keeping the ISO AI standards as candidate-only crosswalks instead of pretending they are already reviewed.
- The medium and issued ExampleCo corridors now also carry narrow password-policy, managed-web-application-firewall, centralized-monitoring, encryption-at-rest, unique-infrastructure-identity, and environment-segmentation controls with typed edge, identity, monitoring, storage, and architecture exports, Lean-backed proofs, refreshed witness material, updated lifecycle drift outputs, and regenerated public signature manifests.
- Draft JSON Schemas for the main machine-readable verification artifacts, now exercised by the public conformance check.
- A draft classification-result artifact and schema for the public prove/attest/judgment routing surface, plus a first public `mixedControls` decomposition format in the medium ExampleCo corridor.
- The proof-runner output now derives Lean batch imports and verified claim bindings from control-boundary metadata and surfaces omitted proved claims as explicit boundary inventory instead of silently dropping them.
- Draft lifecycle and composed-certificate artifacts for drift handling, delta recheck planning, and higher-level certificate composition.
- A draft signed-artifact manifest format plus synthetic public example signature bundles over the issued and lifecycle packs.
- Draft transparency-log and inclusion-proof artifacts plus public transparency outputs for the synthetic ExampleCo corridors.
- A first verifier-release manifest schema plus a versioned public verifier bundle that stitches together the runtime, Lean corridor, specs, evidence schemas, conformance scripts, and current synthetic corridors into one replayable public release.
- The exact-anchor review pilot now also covers 44 public controls across 25 frameworks and 212 review entries, including the public password-policy, managed-web-application-firewall, encryption-at-rest, service-account-key-hygiene, approved-region-boundary, data-subject-rights runbook, vendor-terms, vendor-adequacy, unique-infrastructure-identity, segmentation, incident-runbook, incident-escalation, repository-integrity, secure-baseline, configuration-exception, CI-policy, change-governance, access-review, patch-exception, AI provenance, AI evaluation, and AI data-quality-governance controls, keeping GDPR, IRAP, Cyber Essentials, NCSC CAF, and NIST SP 800-53 at reviewed status where public text supports it, candidate ISO AI mappings where only partial public material exists, and ISO 27001 / SOC 2 as explicit blockers where licensed review is still required.

## What does not exist yet

- No normative schema registry.
- No compatibility guarantees beyond `0.x` draft expectations.
- No production-grade release automation or independent release attestation beyond the current synthetic signed bundle.
- No independent implementation conformance programme.
- No externally reviewed clause-, Annex A-, criterion-, or point-of-focus anchor set for the public corridor yet.
- No live-connector or real-organisation corridors yet for the newer Cyber Essentials and AI-governance controls.
- No public exact-anchor review yet for the ISO AI standards beyond the current candidate layer, and no live-evidence corridor yet for the newer AI provenance, AI evaluation, or AI data-quality-governance controls.

## Publishing rule

If the examples and the specs diverge, the mismatch is a bug.
