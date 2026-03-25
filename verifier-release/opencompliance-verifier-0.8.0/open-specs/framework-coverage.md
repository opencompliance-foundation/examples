# Framework Coverage

This file is a public-safe coverage summary derived from the framework priorities, control-boundary mappings, and exact-anchor review pilot.

## 1. ISO 27001

- Category: `core_assurance`
- Priority tier: `core_now`
- Source availability: `blocked_nonpublic_source_review`
- OpenCompliance state: `private_seed_depth_and_public_family_proxy`
- Mapped public controls: `35`
- Implemented public controls: `35`
- Lean-backed public controls: `21`
- Exact anchors reviewed / candidate / blocked: `0` / `0` / `32`
- Operator benefit: Still the strongest customer-facing security management baseline for SaaS diligence and procurement.
- Next action: Continue private seed decomposition, promote the remaining availability and vulnerability-management slices, and keep blocker-aware exact-anchor review explicit.
- Next depth controls: `oc.backup-01`, `oc.boundary-01`, `oc.cfg-01`, `oc.ci-01`, `oc.crypt-01`, `oc.id-01`, `oc.id-02`, `oc.id-04`

## 2. SOC 2

- Category: `core_assurance`
- Priority tier: `core_now`
- Source availability: `blocked_nonpublic_source_review`
- OpenCompliance state: `private_seed_depth_and_public_family_proxy`
- Mapped public controls: `35`
- Implemented public controls: `35`
- Lean-backed public controls: `21`
- Exact anchors reviewed / candidate / blocked: `0` / `0` / `32`
- Operator benefit: Directly relevant to US buyer assurance, trust-center narratives, and recurring security questionnaires.
- Next action: Continue private seed decomposition and publish only blocker-aware narrow control mappings until licensed criterion review exists.
- Next depth controls: `oc.backup-01`, `oc.boundary-01`, `oc.cfg-01`, `oc.ci-01`, `oc.crypt-01`, `oc.id-01`, `oc.id-02`, `oc.id-04`

## 3. GDPR

- Category: `core_assurance`
- Priority tier: `core_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `17`
- Implemented public controls: `17`
- Lean-backed public controls: `11`
- Exact anchors reviewed / candidate / blocked: `17` / `0` / `0`
- Operator benefit: Directly relevant to UK and EU personal-data handling, customer diligence, and AI systems that process personal data.
- Next action: Maintain the reviewed article-level layer across security of processing, transfer boundaries, data-subject-rights operations, and processor governance, then widen from the current deployer corridor into privacy-by-design and AI-adjacent rights handling.
- Next depth controls: `oc.crypt-01`, `oc.id-01`, `oc.id-04`, `oc.id-05`, `oc.key-01`, `oc.loc-01`, `oc.mon-01`, `oc.net-01`

## 4. IRAP

- Category: `core_assurance`
- Priority tier: `core_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `31`
- Implemented public controls: `31`
- Lean-backed public controls: `21`
- Exact anchors reviewed / candidate / blocked: `36` / `1` / `0`
- Operator benefit: Important for Australian government and regulated-enterprise pathways, especially for a legal-tech deployer pushing into Australia.
- Next action: Maintain the public exact-anchor layer across identity, password, key, locality, boundary, logging, recovery, incident, repository-integrity, secure configuration, change governance, access review, CI-policy, and patch-exception controls, then widen into the remaining hardening and judgment-boundary slices while keeping hosted shared-responsibility assumptions explicit.
- Next depth controls: `oc.patch-03`, `oc.backup-01`, `oc.boundary-01`, `oc.cfg-01`, `oc.ci-01`, `oc.crypt-01`, `oc.id-01`, `oc.id-02`

## 5. EU AI Act

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `7`
- Implemented public controls: `5`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `5` / `3` / `0`
- Operator benefit: Most important binding AI governance regime for EU-facing deployments and for any provable AI transparency or oversight story.
- Next action: Keep the current reviewed articles for risk, oversight, monitoring, and transparency, and only promote the remaining documentation-heavy Article 11 and logging-heavy Article 12 candidates once the typed corridor grows beyond simple signed attestations.
- Next depth controls: `oc.ai-01`, `oc.ai-06`, `oc.ai-05`, `oc.ai-02`, `oc.ai-03`, `oc.ai-04`, `oc.ai-08`

## 6. UK ICO AI and data protection guidance

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `3`
- Implemented public controls: `3`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `3` / `0` / `0`
- Operator benefit: Highly relevant where AI use intersects with personal data, transparency, and UK-regulator expectations.
- Next action: Use the reviewed governance, rights, and transparency anchors now in the pilot, but keep monitoring the guidance refresh triggered by the Data (Use and Access) Act before treating the guidance text as stable long-term anchor inventory.
- Next depth controls: `oc.ai-05`, `oc.ai-01`, `oc.ai-03`

## 7. UK AI Cyber Security Code of Practice

- Category: `ai_security`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `3`
- Implemented public controls: `3`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `3` / `0` / `0`
- Operator benefit: Best near-term public baseline for securing AI systems used or operated by UK software vendors.
- Next action: Keep using the reviewed principles for risk assessment, human responsibility, and monitoring, and widen next into more technical AI security controls only when the public fixture corridor stops being mostly documentary.
- Next depth controls: `oc.ai-02`, `oc.ai-03`, `oc.ai-04`

## 8. NIST AI RMF 1.0

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `7`
- Implemented public controls: `5`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `4` / `0` / `0`
- Operator benefit: Strong voluntary structure for operational AI governance, especially when the company wants a rigorous internal control language without waiting for certification.
- Next action: Keep using it as the backbone public exact-anchor layer for the AI corridor while the GenAI-specific, ETSI, and ISO candidate layers deepen around it.
- Next depth controls: `oc.ai-05`, `oc.ai-07`, `oc.ai-08`, `oc.ai-01`, `oc.ai-02`, `oc.ai-03`, `oc.ai-04`

## 9. NIST AI 600-1 Generative AI Profile

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `7`
- Implemented public controls: `4`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `5` / `0` / `0`
- Operator benefit: Directly relevant for generative-AI deployments and complements the core NIST AI RMF with GenAI-specific risk treatment.
- Next action: Use the reviewed GenAI anchors for context, risk governance, post-deployment monitoring, and content transparency as the first deployer-grade GenAI exact-anchor layer, then widen into additional GAI actions when the fixture corridor grows beyond the current documentary scope.
- Next depth controls: `oc.ai-05`, `oc.ai-07`, `oc.ai-08`, `oc.ai-01`, `oc.ai-02`, `oc.ai-04`, `oc.ai-06`

## 10. NIST AI 100-4

- Category: `ai_assurance`
- Priority tier: `ai_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `1`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `1` / `0` / `0`
- Operator benefit: Highly relevant wherever a legal-tech deployer needs provenance, labeling, authenticity, and disclosure controls for synthetic or transformed content.
- Next action: Use the first reviewed NIST AI 100-4 anchor to keep the new provenance-metadata control honest, then widen from simple metadata presence toward verifiable provenance retention and testing once the public corridor carries richer replayable artifacts.
- Next depth controls: `oc.ai-06`

## 11. ISO/IEC 5338

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `crosswalk_candidate_only`
- Mapped public controls: `1`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `1` / `0`
- Operator benefit: Useful for turning AI lifecycle work into a process model that sits between RMF-style governance language and concrete engineering controls.
- Next action: Use the public abstract to shape candidate lifecycle and evaluation-control families now, but keep every clause-grade anchor explicitly blocked behind licensed review.
- Next depth controls: `oc.ai-07`

## 12. ISO/IEC 42001

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `crosswalk_candidate_only`
- Mapped public controls: `7`
- Implemented public controls: `5`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `0` / `6` / `0`
- Operator benefit: Most obvious management-system-style target for organisations that want AI governance to look certifiable and auditable.
- Next action: Keep publishing only crosswalk-derived candidate anchors until licensed clause review exists.
- Next depth controls: `oc.ai-05`, `oc.ai-01`, `oc.ai-02`, `oc.ai-03`, `oc.ai-04`, `oc.ai-06`, `oc.ai-08`

## 13. ISO/IEC 42005

- Category: `ai_governance`
- Priority tier: `ai_now`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `crosswalk_candidate_only`
- Mapped public controls: `4`
- Implemented public controls: `3`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `3` / `0`
- Operator benefit: Useful for impact-assessment depth and for turning AI risk work into a more explicit, reviewable artifact chain.
- Next action: Use it to shape impact-assessment-oriented claim types and candidate exact-anchor plans.
- Next depth controls: `oc.ai-01`, `oc.ai-02`, `oc.ai-04`, `oc.ai-07`

## 14. ISO/IEC 5259-5

- Category: `ai_governance`
- Priority tier: `candidate_next`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `crosswalk_candidate_only`
- Mapped public controls: `1`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `1` / `0`
- Operator benefit: Relevant for board-level data-quality governance where AI outputs depend on trustworthy source, training, or evaluation data.
- Next action: Use the published standard summary to shape the new planned data-quality-governance control now, but keep exact clause publication blocked until licensed review exists.
- Next depth controls: `oc.ai-08`

## 15. Australia Voluntary AI Safety Standard

- Category: `ai_governance`
- Priority tier: `regional_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `6`
- Implemented public controls: `5`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `6` / `0` / `0`
- Operator benefit: Relevant for Australian deployments and especially useful because it is deployer-oriented and openly structured as ten guardrails.
- Next action: Keep treating it as the Australian public-anchor bridge for context, risk, oversight, monitoring, and disclosure controls, then add more operational slices only when the public AI corridor includes live evaluation and deployment evidence.
- Next depth controls: `oc.ai-05`, `oc.ai-01`, `oc.ai-02`, `oc.ai-03`, `oc.ai-04`, `oc.ai-06`

## 16. ETSI EN 304 223

- Category: `ai_security`
- Priority tier: `regional_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `1`
- Implemented public controls: `1`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `1` / `0` / `0`
- Operator benefit: Strong European baseline for AI cybersecurity, especially useful if a legal-tech deployer wants a public AI security story beyond governance prose.
- Next action: Use the reviewed monitoring and incident-handling anchor as the first ETSI AI security foothold, then widen into supply-chain and secure-development provisions when there is a real public AI security corridor to attach them to.
- Next depth controls: `oc.ai-04`

## 17. ETSI TS 104 008

- Category: `ai_assurance`
- Priority tier: `regional_now`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `1`
- Implemented public controls: `1`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `1` / `0` / `0`
- Operator benefit: Directly relevant to OpenCompliance itself because it frames continuous auditing-based conformity assessment for dynamic AI systems.
- Next action: Use the reviewed continuous-auditing anchor to shape the transparency, witness, and continuous-verification plane, then widen only when the public runtime can emit richer monitoring and conformity-assessment evidence.
- Next depth controls: `oc.ai-04`

## 18. ISO/IEC 23894

- Category: `ai_governance`
- Priority tier: `candidate_next`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `crosswalk_candidate_only`
- Mapped public controls: `2`
- Implemented public controls: `2`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `2` / `0`
- Operator benefit: Useful for risk-management language and audit conversations, but not as primary as 42001 or 42005 for the current corridor.
- Next action: Keep it as a candidate exact-anchor layer behind NIST AI RMF and 42001 until licensed review exists.
- Next depth controls: `oc.ai-02`, `oc.ai-04`

## 19. NIST SP 800-218A

- Category: `ai_security`
- Priority tier: `candidate_next`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `priority_backlog`
- Mapped public controls: `0`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `0` / `0`
- Operator benefit: High-value if a legal-tech deployer wants to prove GenAI-aware secure development practices rather than only governance documentation.
- Next action: Use it to shape future secure-development and model-lifecycle controls, not the current documentary AI-governance corridor.

## 20. NIST AI 700-2

- Category: `ai_assurance`
- Priority tier: `candidate_next`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `1`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `1` / `0` / `0`
- Operator benefit: Useful for a future evaluation layer that needs structured evidence about AI risks and impacts rather than only governance attestations.
- Next action: Use the first reviewed ARIA anchor to shape the new planned AI-evaluation control now, then widen from signed evaluation records toward reproducible testing and field-evaluation bundles when the public fixture surface can carry them.
- Next depth controls: `oc.ai-07`

## 21. EU GPAI Code of Practice

- Category: `ai_governance`
- Priority tier: `candidate_next`
- Source availability: `public_exact_feasible`
- OpenCompliance state: `public_exact_anchor_review_available`
- Mapped public controls: `1`
- Implemented public controls: `1`
- Lean-backed public controls: `1`
- Exact anchors reviewed / candidate / blocked: `1` / `0` / `0`
- Operator benefit: Important if a legal-tech deployer ever trains, fine-tunes, or meaningfully distributes general-purpose models instead of only deploying third-party models.
- Next action: Keep it in the review layer but avoid over-prioritising it unless the operating model changes toward GPAI provider responsibilities.
- Next depth controls: `oc.ai-05`

## 22. NIST AI 800-1

- Category: `ai_security`
- Priority tier: `emerging_draft`
- Source availability: `public_draft`
- OpenCompliance state: `emerging_backlog`
- Mapped public controls: `0`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `0` / `0`
- Operator benefit: Potentially important for dual-use or foundation-model misuse risk, but still draft and less immediately relevant for ordinary deployer controls.
- Next action: Track the draft and use it to shape future foundation-model misuse controls only if the operator expands into that risk class.

## 23. ISO/IEC AWI 25704

- Category: `ai_assurance`
- Priority tier: `emerging_draft`
- Source availability: `public_draft`
- OpenCompliance state: `emerging_backlog`
- Mapped public controls: `1`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `1` / `0`
- Operator benefit: Potentially useful for future process-capability assessment of AI life cycle work, but still too early for direct control mapping.
- Next action: Use the public abstract as a candidate pointer for future process-assessment artifacts, but keep draft maturity and clause-level mapping clearly outside the reviewed public layer.
- Next depth controls: `oc.ai-07`

## 24. ISO/IEC 42006

- Category: `ai_assurance`
- Priority tier: `ecosystem_watch`
- Source availability: `crosswalk_candidate`
- OpenCompliance state: `ecosystem_backlog`
- Mapped public controls: `0`
- Implemented public controls: `0`
- Lean-backed public controls: `0`
- Exact anchors reviewed / candidate / blocked: `0` / `0` / `0`
- Operator benefit: Relevant to the audit and certification ecosystem around AI management systems, but not a direct first-order operator control framework.
- Next action: Track it as ecosystem infrastructure for the certification layer rather than as an immediate control-mapping target.

