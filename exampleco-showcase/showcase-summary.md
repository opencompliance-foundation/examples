# ExampleCo OpenCompliance Showcase

**Showcase:** `exampleco-opencompliance-showcase-2026-03-24`  
**Generated:** `2026-03-24T18:20:00Z`  
**Canonical site:** `https://opencompliancefoundation.com/`  
**Repository map:** `https://opencompliancefoundation.com/repositories.html`

Show how a hypothetical company could use OpenCompliance to publish corridor-scoped proof, attestation, and failure artifacts without pretending that whole standards are fully proved.

## What this pack demonstrates

- `4` scoped corridors
- `3` issued outcomes and `1` blocked outcome
- `16` proved claims across the showcased corridors
- `10` attested claims across the showcased corridors
- `1` failed claim, `1` judgment-required claim, and `0` evidence-missing claims across the selected corridors

The right public statement is not that ExampleCo is fully certified. The right statement is that ExampleCo can publish a replayable package showing exactly what is proved, what is attested, and what still blocks issuance for each scoped corridor.

## Workflow

- **Define narrow corridors**: Split the company posture into scoped corridors such as cyber hygiene, issued mixed controls, AI governance, and blocked or stale slices.
- **Collect typed evidence and attestations**: Publish machine-state exports where possible and keep documentary governance evidence as signed attestation claims.
- **Run Verify per corridor**: Generate corridor-specific proof bundles, trust-surface reports, verification results, and either a scoped certificate or a typed punch-list.
- **Publish only public-safe artifacts**: Expose trust-surface reports, replay bundles, witness receipts, transparency logs, and OSCAL-shaped projections without leaking private operational data.
- **Let third parties inspect and replay**: Give buyers and reviewers a package they can inspect corridor by corridor instead of one flattened compliance claim.

## Corridor summaries

### Cyber baseline corridor (`cyber-baseline`)

- **Outcome**: `certificate_issued`
- **Claim summary**: proved `5`, attested `0`, failed `0`, stale `0`, judgment `0`, missing `0`
- **Safe statement**: ExampleCo can state that the managed admin and endpoint baseline enforces MFA, default-deny network boundaries, secure configuration, timely patching, and malware protection for the scoped fleet.
- **Why included**: This is the simplest corridor for buyers who want to see what a genuinely provable slice looks like today.
- **Frameworks touched**: Cyber Essentials, GDPR, IRAP, ISO 27001, NCSC CAF 4.0, NIST CSF 2.0, NIST SP 800-53 Rev. 5.1, SOC 2
- **Artifacts**: `cyber-baseline/trust-surface-report.md`, `cyber-baseline/verification-result.json`, `cyber-baseline/certificate.json`

### Issued mixed corridor (`issued`)

- **Outcome**: `certificate_issued`
- **Claim summary**: proved `9`, attested `5`, failed `0`, stale `0`, judgment `0`, missing `0`
- **Safe statement**: ExampleCo can state that the scoped identity, logging, access-review, training, restore, and incident-runbook corridor has no blocking gaps, while still disclosing which parts are proved and which parts are attested.
- **Why included**: This demonstrates the most realistic near-term success path: some controls are proved, others remain documentary, and the certificate still stays narrow.
- **Frameworks touched**: Cyber Essentials, GDPR, IRAP, ISO 27001, NCSC CAF 4.0, NIST CSF 2.0, NIST SP 800-53 Rev. 5.1, SOC 2
- **Artifacts**: `issued/trust-surface-report.md`, `issued/verification-result.json`, `issued/certificate.json`

### AI governance corridor (`ai-governance`)

- **Outcome**: `certificate_issued`
- **Claim summary**: proved `1`, attested `4`, failed `0`, stale `0`, judgment `0`, missing `0`
- **Safe statement**: ExampleCo can state that AI context, risk process, oversight, and monitoring are documented and signed, and that AI-generated content disclosure is mechanically demonstrated on the scoped assistant surface.
- **Why included**: This keeps AI marketing honest by separating documentary governance evidence from the one narrow technical control that is currently machine-checkable.
- **Frameworks touched**: EU AI Act, EU GPAI Code of Practice, ISO/IEC 23894, ISO/IEC 42001, ISO/IEC 42005, NIST AI RMF 1.0
- **Artifacts**: `ai-governance/trust-surface-report.md`, `ai-governance/verification-result.json`, `ai-governance/certificate.json`

### Blocked corridor (`failed`)

- **Outcome**: `punch_list_issued`
- **Claim summary**: proved `1`, attested `1`, failed `1`, stale `0`, judgment `1`, missing `0`
- **Safe statement**: ExampleCo can state that this corridor is not issuance-ready, and can hand over a typed punch-list showing exactly which controls failed or still require human judgment.
- **Why included**: A trustworthy framework must show honest failure paths rather than only polished success cases.
- **Frameworks touched**: ISO 27001, SOC 2
- **Artifacts**: `failed/trust-surface-report.md`, `failed/verification-result.json`, `failed/punch-list.json`

## Framework view

### Cyber Essentials

- **Public position**: Narrow public cyber hygiene corridor with clean machine-checkable examples, not a full certification claim.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `7`, attested `0`, failed `0`, stale `0`, judgment `0`, missing `0`

### EU AI Act

- **Public position**: Documentary AI-governance corridor plus one machine-checkable disclosure control, not full legal compliance.
- **Corridors**: ai-governance
- **Claim summary**: proved `1`, attested `4`, failed `0`, stale `0`, judgment `0`, missing `0`

### EU GPAI Code of Practice

- **Public position**: Transparency-focused AI example corridor only, not complete code adherence.
- **Corridors**: ai-governance
- **Claim summary**: proved `1`, attested `0`, failed `0`, stale `0`, judgment `0`, missing `0`

### GDPR

- **Public position**: Framework-adjacent family mappings appear in the public cyber corridor, but adequacy and legal interpretation remain outside the proved slice.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `7`, attested `1`, failed `0`, stale `0`, judgment `0`, missing `0`

### IRAP

- **Public position**: Family-level overlap only in the current public example packs, not a complete IRAP assessment.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `11`, attested `3`, failed `0`, stale `0`, judgment `0`, missing `0`

### ISO 27001

- **Public position**: Family-proxy and corridor-scoped examples only, not clause-level certification or full Annex A coverage.
- **Corridors**: cyber-baseline, failed, issued
- **Claim summary**: proved `15`, attested `6`, failed `1`, stale `0`, judgment `1`, missing `0`

### ISO/IEC 23894

- **Public position**: AI risk guidance appears in the AI-governance example as attested process evidence, not a complete standard implementation.
- **Corridors**: ai-governance
- **Claim summary**: proved `0`, attested `2`, failed `0`, stale `0`, judgment `0`, missing `0`

### ISO/IEC 42001

- **Public position**: AI management system family mappings appear in the AI-governance corridor, but the public slice stays narrow and mixed.
- **Corridors**: ai-governance
- **Claim summary**: proved `1`, attested `4`, failed `0`, stale `0`, judgment `0`, missing `0`

### ISO/IEC 42005

- **Public position**: Impact-assessment-related family mappings appear in the AI-governance corridor, not a complete impact assessment regime.
- **Corridors**: ai-governance
- **Claim summary**: proved `0`, attested `3`, failed `0`, stale `0`, judgment `0`, missing `0`

### NCSC CAF 4.0

- **Public position**: Crosswalked family-level support only in the cyber baseline corridor.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `5`, attested `1`, failed `0`, stale `0`, judgment `0`, missing `0`

### NIST AI RMF 1.0

- **Public position**: AI governance and transparency families appear in the synthetic AI corridor, still mostly attestation-backed.
- **Corridors**: ai-governance
- **Claim summary**: proved `1`, attested `4`, failed `0`, stale `0`, judgment `0`, missing `0`

### NIST CSF 2.0

- **Public position**: Crosswalked family-level support only in the cyber baseline corridor.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `11`, attested `1`, failed `0`, stale `0`, judgment `0`, missing `0`

### NIST SP 800-53 Rev. 5.1

- **Public position**: Crosswalked family-level support only in the cyber baseline corridor.
- **Corridors**: cyber-baseline, issued
- **Claim summary**: proved `11`, attested `1`, failed `0`, stale `0`, judgment `0`, missing `0`

### SOC 2

- **Public position**: Narrow corridor evidence only, not a full opinion or clause-complete public mapping corpus.
- **Corridors**: cyber-baseline, failed, issued
- **Claim summary**: proved `15`, attested `4`, failed `1`, stale `0`, judgment `1`, missing `0`

## Rebuild and check

Inside the private working tree:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/build_showcase_manifest.py --showcase-root fixtures/public/exampleco-showcase --check
```

Inside a public multi-repo checkout:

```sh
cd conformance
python3 scripts/build_showcase_manifest.py --examples-root ../examples --showcase-root exampleco-showcase --check

cd conformance
python3 scripts/validate_public_examples.py --examples-root ../examples --specs-root ../specs --schema-root ../evidence-schema
```

## Public roots

- Showcase repo root: https://github.com/opencompliance-foundation/examples/tree/main/exampleco-showcase
- Showcase report: https://github.com/opencompliance-foundation/examples/blob/main/exampleco-showcase/showcase-report.json
- Showcase summary: https://github.com/opencompliance-foundation/examples/blob/main/exampleco-showcase/showcase-summary.md
- Builder script: https://github.com/opencompliance-foundation/conformance/blob/main/scripts/build_showcase_manifest.py

