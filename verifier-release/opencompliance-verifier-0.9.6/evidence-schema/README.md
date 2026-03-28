# OpenCompliance Evidence Schema

This directory is the private source of truth for the public export to `opencompliance-foundation/evidence-schema`.

The first release publishes a draft envelope for typed evidence claims and a small set of claim-type payload schemas aligned to the public synthetic examples.

## Current contents

- `STATUS.md`
- `schemas/evidence-claim.schema.json`
- `schemas/claim-types/*.schema.json`
- `examples/evidence-claim.example.json`
- `examples/evidence-claim.delegated-approver.example.json`

## Current notes

- The schema set now covers the current synthetic claim types used by the minimal, failed, medium, stale, issued, cyber-baseline, and AI-governance ExampleCo corridors, including repo-policy and CI-policy connector examples, typed password-policy, managed-WAF, centralized-monitoring, storage-encryption, infrastructure-identity-uniqueness, and environment-segmentation exports for the newer decidable corridor slices, change-review, access-review-closure, monitoring-review, vendor-terms, and incident-governance attestations in the medium or issued packs, freshness-downgraded evidence in the stale pack, Cyber Essentials-style cyber hygiene exports, and AI-governance attestations plus AI disclosure state.
- The schema set now also covers the newly promoted conduct, internal-audit, customer-support, workspace-hygiene, and security-community public controls through typed attestation payloads such as code-of-conduct, conduct-governance, disciplinary-policy, disciplinary-action, internal-audit program and execution, customer-support channel and governance, clear-desk / clear-screen policy and coverage, and security-community membership or output-review attestations.
- The schema set now also includes the next promoted planned claim types for continuity-plan attestations, risk-management process and cycle attestations, retention/deletion governance attestations, facility cabling and supporting-utility attestations, agreement security-commitment attestations, ISMS context attestations, project-security attestations, security-concern handling attestations, outsourced-development governance attestations, ISMS stakeholder-register and stakeholder-obligation attestations, corrective-action process and follow-up attestations, compliance-requirement register and review attestations, intellectual-property policy and issue-handling attestations, and remote-access or remote-working attestations, alongside the earlier candidate claim types for future expansions beyond the current public corridors such as configuration and patch exceptions, vendor or patch adequacy-boundary support artifacts, and the next AI-assurance layer for provenance metadata, structured evaluation records, and data-quality governance attestations.
- The public schema now exposes the widened actor envelope: delegated approvers are first-class in evidence claims, trust-policy references are carried in the claim envelope, and signer metadata now includes signed time, signer role, trust-policy linkage, and delegation metadata where required.
- Verifier-service and independent-witness identities are represented in the public trust-policy registry and signing or witness artifacts, and the release line now also publishes explicit trust-root profiles for synthetic fallback versus environment-supplied release and witness identities, even though the current public evidence corridors still only exercise system, human-owner, and delegated-approver evidence claims.
