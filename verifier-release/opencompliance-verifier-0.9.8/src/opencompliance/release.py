from __future__ import annotations


PUBLIC_VERIFIER_NAME = "opencompliance-verifier"
PUBLIC_VERIFIER_SEMVER = "0.9.8"
PUBLIC_VERIFIER_VERSION = f"{PUBLIC_VERIFIER_NAME}/{PUBLIC_VERIFIER_SEMVER}"
PUBLIC_VERIFIER_RELEASE_ID = f"{PUBLIC_VERIFIER_NAME}-{PUBLIC_VERIFIER_SEMVER}"
PUBLIC_VERIFIER_RELEASED_AT = "2026-03-28T06:34:36Z"
PUBLIC_VERIFIER_LAYOUT_VERSION = 1
PUBLIC_VERIFIER_CONTRACT_ID = "opencompliance-public-verifier-contract-v7"
PUBLIC_VERIFIER_CONTRACT_VERSION = 7
PUBLIC_VERIFIER_RELEASE_SCHEMA_URL = "https://opencompliancefoundation.com/specs/schemas/verifier-release.schema.json"
PUBLIC_VERIFIER_CONTRACT_SCHEMA_URL = "https://opencompliancefoundation.com/specs/schemas/verifier-contract.schema.json"
PUBLIC_VERIFIER_RELEASE_ATTESTATION_SCHEMA_URL = "https://opencompliancefoundation.com/specs/schemas/release-attestation.schema.json"
PUBLIC_VERIFIER_CONTRACT_PATH = "open-specs/verifier-contract.json"
PUBLIC_VERIFIER_TRUST_REGISTRIES = {
    "actorTrustPolicies": {
        "relativeTo": "releaseRoot",
        "path": "open-specs/actor-trust-policies.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/actor-trust-policies.schema.json",
        "required": True,
    },
    "actorIdentities": {
        "relativeTo": "releaseRoot",
        "path": "open-specs/actor-identities.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/actor-identities.schema.json",
        "required": True,
    },
    "connectorIngressProfiles": {
        "relativeTo": "releaseRoot",
        "path": "open-specs/connector-ingress-profiles.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/connector-ingress-profiles.schema.json",
        "required": True,
    },
    "trustRootProfiles": {
        "relativeTo": "releaseRoot",
        "path": "open-specs/trust-root-profiles.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/trust-root-profiles.schema.json",
        "required": True,
    },
}
PUBLIC_VERIFIER_INCLUDED_FIXTURES = (
    "minimal",
    "failed",
    "stale",
    "medium",
    "issued",
    "cyber-baseline",
    "ai-governance",
)
PUBLIC_VERIFIER_ENTRYPOINTS = {
    "verifyFixture": "scripts/verify_fixture.py",
    "serveVerifyApi": "scripts/serve_verify_api.py",
    "localVerifyWorkbench": "ui/verify/index.html",
    "runLeanBatch": "scripts/run_lean_batch.py",
    "attestReleaseBundle": "scripts/attest_release_bundle.py",
    "validateExamples": "conformance/scripts/validate_public_examples.py",
    "verifySignedArtifacts": "scripts/verify_signed_artifacts.py",
    "verifyTransparency": "scripts/verify_transparency_log.py",
}
PUBLIC_VERIFIER_INCLUDED_ROOTS = (
    "src/",
    "scripts/",
    "open-specs/",
    "lean4-controls/",
    "evidence-schema/",
    "conformance/",
    "docs/",
    "ui/",
    "fixtures/public/",
)
PUBLIC_VERIFIER_CONTROL_ROUTES = (
    "decidable",
    "attestation",
    "judgment",
)
PUBLIC_VERIFIER_CLAIM_RESULTS = (
    "proved",
    "attested",
    "failed",
    "stale_evidence",
    "judgment_required",
    "evidence_missing",
)
PUBLIC_VERIFIER_SUMMARY_FIELDS = (
    "proved",
    "attested",
    "failed",
    "staleEvidence",
    "judgmentRequired",
    "evidenceMissing",
)
PUBLIC_VERIFIER_PROOF_RUNNER_STATUSES = ("verified",)
PUBLIC_VERIFIER_TYPED_BOUNDARY_SOURCE = "LegalLean"
PUBLIC_VERIFIER_TYPED_BOUNDARY_MODULES = (
    "OpenCompliance.Controls.Typed.TypedIdentity",
    "OpenCompliance.Controls.Typed.TypedLogging",
    "OpenCompliance.Controls.Typed.RiskAcceptance",
    "OpenCompliance.Controls.Typed.DiscretionaryTerms",
    "OpenCompliance.Controls.Typed.ComplianceSolver",
    "OpenCompliance.Controls.Typed.PublicRuntime",
)
PUBLIC_VERIFIER_TYPED_BOUNDARY_MODULE_COVERAGE = {
    "OpenCompliance.Controls.Typed.TypedIdentity": [
        "FormalisationBoundary.formal",
        "FormalisationBoundary.boundary",
        "RequiresHumanDetermination",
    ],
    "OpenCompliance.Controls.Typed.TypedLogging": [
        "FormalisationBoundary.formal",
        "FormalisationBoundary.boundary",
        "narrow_audit_logging_runtime",
    ],
    "OpenCompliance.Controls.Typed.RiskAcceptance": [
        "Defeats",
        "risk_acceptance_override",
    ],
    "OpenCompliance.Controls.Typed.DiscretionaryTerms": [
        "Vague",
        "judgment_boundary_inventory",
    ],
    "OpenCompliance.Controls.Typed.ComplianceSolver": [
        "LegalLean.Solver",
        "minimal_claim_corpus",
        "runtime_claim_decisions",
    ],
    "OpenCompliance.Controls.Typed.PublicRuntime": [
        "formalDecision",
        "documentaryDecision",
        "judgmentDecision",
        "public_corridor_runtime_claim_decisions",
    ],
}
PUBLIC_VERIFIER_TYPED_BOUNDARY_STATUS_FLAGS = (
    "typedControlResultsLive",
    "riskAcceptanceDefeasibilityLive",
    "discretionaryTermTypingLive",
    "fullMinimalSolverAgreement",
    "pythonVerdictLayerReplaced",
)
PUBLIC_VERIFIER_RELEASE_ARTIFACTS = {
    "releaseManifest": {
        "relativeTo": "releaseRoot",
        "path": "release-manifest.json",
        "schema": PUBLIC_VERIFIER_RELEASE_SCHEMA_URL,
        "required": True,
    },
    "verifierContract": {
        "relativeTo": "releaseRoot",
        "path": PUBLIC_VERIFIER_CONTRACT_PATH,
        "schema": "https://opencompliancefoundation.com/specs/schemas/verifier-contract.schema.json",
        "required": True,
    },
    "signedArtifactManifest": {
        "relativeTo": "releaseRoot",
        "path": "signed-artifact-manifest.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/signed-artifact-manifest.schema.json",
        "required": True,
    },
    "publicKey": {
        "relativeTo": "releaseRoot",
        "path": "public-key.pem",
        "contentType": "application/x-pem-file",
        "required": True,
    },
    "releaseAttestation": {
        "relativeTo": "releaseRoot",
        "path": "release-attestation.json",
        "schema": PUBLIC_VERIFIER_RELEASE_ATTESTATION_SCHEMA_URL,
        "required": True,
    },
}
PUBLIC_VERIFIER_FIXTURE_ARTIFACTS = {
    "classificationResult": {
        "relativeTo": "fixtureRoot",
        "path": "classification-result.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/classification-result.schema.json",
        "required": True,
    },
    "proofBundle": {
        "relativeTo": "fixtureRoot",
        "path": "proof-bundle.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/proof-bundle.schema.json",
        "required": True,
    },
    "verificationResult": {
        "relativeTo": "fixtureRoot",
        "path": "verification-result.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/verification-result.schema.json",
        "required": True,
    },
    "replayBundle": {
        "relativeTo": "fixtureRoot",
        "path": "replay-bundle.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/replay-bundle.schema.json",
        "required": True,
    },
    "transparencyLog": {
        "relativeTo": "fixtureRoot",
        "path": "transparency-log.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/transparency-log.schema.json",
        "required": True,
    },
    "inclusionProofs": {
        "relativeTo": "fixtureRoot",
        "path": "inclusion-proofs.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/inclusion-proofs.schema.json",
        "required": True,
    },
    "witnessReceipt": {
        "relativeTo": "fixtureRoot",
        "path": "witness-receipt.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/witness-receipt.schema.json",
        "required": True,
    },
    "revocation": {
        "relativeTo": "fixtureRoot",
        "path": "revocation.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/revocation.schema.json",
        "required": True,
    },
    "trustSurfaceReport": {
        "relativeTo": "fixtureRoot",
        "path": "trust-surface-report.md",
        "contentType": "text/markdown",
        "required": True,
    },
    "oscalAssessmentResults": {
        "relativeTo": "fixtureRoot",
        "pathPattern": "oscal/*assessment-results.json",
        "contentType": "application/json",
        "required": True,
    },
    "certificate": {
        "relativeTo": "fixtureRoot",
        "path": "certificate.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/certificate.schema.json",
        "required": False,
    },
    "punchList": {
        "relativeTo": "fixtureRoot",
        "path": "punch-list.json",
        "schema": "https://opencompliancefoundation.com/specs/schemas/punch-list.schema.json",
        "required": False,
    },
}
PUBLIC_VERIFIER_OUTCOME_POLICIES = {
    "alwaysRequired": (
        "classificationResult",
        "proofBundle",
        "verificationResult",
        "replayBundle",
        "transparencyLog",
        "inclusionProofs",
        "witnessReceipt",
        "revocation",
        "trustSurfaceReport",
        "oscalAssessmentResults",
    ),
    "byVerificationOutcome": {
        "certificate_issued": ("certificate",),
        "punch_list_issued": ("punchList",),
    },
}
PUBLIC_VERIFIER_API_SURFACE = {
    "transport": "http-json-local",
    "defaultHost": "127.0.0.1",
    "defaultPort": 8788,
    "requestModes": [
        "fixture_path",
        "inline_bundle",
    ],
    "endpoints": {
        "healthz": {
            "method": "GET",
            "path": "/healthz",
        },
        "fixtures": {
            "method": "GET",
            "path": "/fixtures",
        },
        "contract": {
            "method": "GET",
            "path": "/contract",
        },
        "verify": {
            "method": "POST",
            "path": "/verify",
        },
    },
}


def build_public_verifier_contract() -> dict[str, object]:
    return {
        "$schema": PUBLIC_VERIFIER_CONTRACT_SCHEMA_URL,
        "contractId": PUBLIC_VERIFIER_CONTRACT_ID,
        "contractVersion": PUBLIC_VERIFIER_CONTRACT_VERSION,
        "verifierVersion": PUBLIC_VERIFIER_VERSION,
        "releaseId": PUBLIC_VERIFIER_RELEASE_ID,
        "releaseGeneratedAt": PUBLIC_VERIFIER_RELEASED_AT,
        "bundleLayoutVersion": PUBLIC_VERIFIER_LAYOUT_VERSION,
        "includedFixtures": list(PUBLIC_VERIFIER_INCLUDED_FIXTURES),
        "entrypoints": PUBLIC_VERIFIER_ENTRYPOINTS,
        "includedRoots": list(PUBLIC_VERIFIER_INCLUDED_ROOTS),
        "releaseArtifacts": PUBLIC_VERIFIER_RELEASE_ARTIFACTS,
        "trustRegistries": PUBLIC_VERIFIER_TRUST_REGISTRIES,
        "fixtureArtifacts": PUBLIC_VERIFIER_FIXTURE_ARTIFACTS,
        "artifactPolicies": {
            "alwaysRequired": list(PUBLIC_VERIFIER_OUTCOME_POLICIES["alwaysRequired"]),
            "byVerificationOutcome": {
                outcome: list(artifacts)
                for outcome, artifacts in PUBLIC_VERIFIER_OUTCOME_POLICIES["byVerificationOutcome"].items()
            },
        },
        "apiSurface": PUBLIC_VERIFIER_API_SURFACE,
        "typedBoundary": {
            "source": PUBLIC_VERIFIER_TYPED_BOUNDARY_SOURCE,
            "controlRoutes": list(PUBLIC_VERIFIER_CONTROL_ROUTES),
            "claimResults": list(PUBLIC_VERIFIER_CLAIM_RESULTS),
            "summaryFields": list(PUBLIC_VERIFIER_SUMMARY_FIELDS),
            "proofRunnerStatuses": list(PUBLIC_VERIFIER_PROOF_RUNNER_STATUSES),
            "requiredTypedModules": list(PUBLIC_VERIFIER_TYPED_BOUNDARY_MODULES),
            "requiredModuleCoverage": PUBLIC_VERIFIER_TYPED_BOUNDARY_MODULE_COVERAGE,
            "requiredRuntimeStatusFlags": list(PUBLIC_VERIFIER_TYPED_BOUNDARY_STATUS_FLAGS),
            "requiredBoundaryInventoryFields": [
                "provedClaimCount",
                "leanBackedClaimCount",
                "omittedProvedClaims",
            ],
        },
        "notes": [
            "This contract describes the current synthetic public verifier release, not arbitrary live-organisation inputs.",
            "The public verifier contract covers runtime-consumed claims, typed boundary metadata, release artifacts, and per-fixture output expectations.",
            "The local Verify API is now part of the contract surface, but it is still scoped to the current synthetic corridor shapes and known OSCAL seeds rather than arbitrary live-organisation bundles.",
            "The release-level attestation artifact records bundle self-replay and transparency verification under an explicit witness identity, while the signed bundle manifest remains a separate verification surface.",
            "System-export evidence claims are now constrained by a published connector-ingress registry keyed to registered system actor identities, and the release line now also carries explicit trust-root profiles for synthetic fallback versus environment-supplied release and witness identities.",
            "The public reference release still uses synthetic trust roots by default; live publication roots are now an implemented but opt-in path rather than an undocumented future idea.",
        ],
    }
