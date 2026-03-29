from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .actor_ontology import (
    INDEPENDENT_WITNESS_POLICY_ID,
    VERIFIER_SERVICE_POLICY_ID,
    validate_registered_identity,
)


SYNTHETIC_RELEASE_SIGNER_PROFILE_ID = "oc.trust-root.synthetic-release-signer"
ENV_RELEASE_SIGNER_PROFILE_ID = "oc.trust-root.environment-release-signer"
SYNTHETIC_RELEASE_WITNESS_PROFILE_ID = "oc.trust-root.synthetic-release-witness"
ENV_RELEASE_WITNESS_PROFILE_ID = "oc.trust-root.environment-release-witness"

RELEASE_SIGNER_ID_ENV = "OPENCOMPLIANCE_RELEASE_SIGNER_ID"
RELEASE_SIGNER_KEY_ID_ENV = "OPENCOMPLIANCE_RELEASE_SIGNER_KEY_ID"
RELEASE_SIGNER_PRIVATE_KEY_ENV = "OPENCOMPLIANCE_RELEASE_PRIVATE_KEY_PATH"
RELEASE_SIGNER_PUBLIC_KEY_ENV = "OPENCOMPLIANCE_RELEASE_PUBLIC_KEY_PATH"
RELEASE_SIGNER_ROLE_ENV = "OPENCOMPLIANCE_RELEASE_SIGNER_ROLE"

RELEASE_WITNESS_MODE_ENV = "OPENCOMPLIANCE_RELEASE_WITNESS_MODE"
RELEASE_WITNESS_ID_ENV = "OPENCOMPLIANCE_RELEASE_WITNESS_ID"
RELEASE_WITNESS_ROLE_ENV = "OPENCOMPLIANCE_RELEASE_WITNESS_ROLE"

SYNTHETIC_RELEASE_SIGNER = {
    "signerId": "oc-synthetic-signer",
    "signerType": "verifier_service",
    "signerRole": "release_signer",
    "trustPolicyId": VERIFIER_SERVICE_POLICY_ID,
    "keyId": "oc-synthetic-ed25519-001",
    "algorithm": "Ed25519",
    "publicKeyPath": "public-key.pem",
}

TRUST_ROOT_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "profileId": SYNTHETIC_RELEASE_SIGNER_PROFILE_ID,
        "surface": "signed_artifact",
        "mode": "synthetic_reference",
        "description": "Synthetic verifier-service signing root used by the public reference release line.",
        "actorType": "verifier_service",
        "role": "release_signer",
        "trustPolicyId": VERIFIER_SERVICE_POLICY_ID,
        "identityId": "oc-synthetic-signer",
        "fallbackIdentityId": "oc-synthetic-signer",
        "keyId": "oc-synthetic-ed25519-001",
        "publicKeyPath": "public-key.pem",
        "privateKeyPath": "fixtures/internal/signing/exampleco-synthetic-ed25519-private-key.pem",
        "environmentVariables": [],
        "syntheticFallbackAllowed": True,
        "notes": [
            "This is the default publication root for the public reference release line.",
            "It is intentionally synthetic and public-safe.",
        ],
    },
    {
        "profileId": ENV_RELEASE_SIGNER_PROFILE_ID,
        "surface": "signed_artifact",
        "mode": "environment_override",
        "description": "Environment-supplied verifier-service signing root for non-synthetic release publication.",
        "actorType": "verifier_service",
        "role": "release_signer",
        "trustPolicyId": VERIFIER_SERVICE_POLICY_ID,
        "identityId": "oc-live-release-signer",
        "fallbackIdentityId": "oc-synthetic-signer",
        "keyId": "env-supplied",
        "publicKeyPath": "public-key.pem",
        "privateKeyPath": "",
        "environmentVariables": [
            RELEASE_SIGNER_PRIVATE_KEY_ENV,
            RELEASE_SIGNER_PUBLIC_KEY_ENV,
        ],
        "syntheticFallbackAllowed": True,
        "notes": [
            "This profile becomes active only when the release signing key paths are supplied through the environment.",
            "The signer identity defaults to oc-live-release-signer but may be overridden by environment for a differently registered verifier-service identity.",
            "This path is implemented but not exercised by the public reference release.",
        ],
    },
    {
        "profileId": SYNTHETIC_RELEASE_WITNESS_PROFILE_ID,
        "surface": "release_attestation",
        "mode": "synthetic_reference",
        "description": "Synthetic independent witness identity used by the public reference release attestation.",
        "actorType": "independent_witness",
        "role": "independent_replay_witness",
        "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
        "identityId": "oc-synthetic-release-witness",
        "fallbackIdentityId": "oc-synthetic-release-witness",
        "keyId": "",
        "publicKeyPath": "",
        "privateKeyPath": "",
        "environmentVariables": [],
        "syntheticFallbackAllowed": True,
        "notes": [
            "This is the default witness identity for the public reference release line.",
            "It remains synthetic until an environment-supplied or externally trusted witness root is configured.",
        ],
    },
    {
        "profileId": ENV_RELEASE_WITNESS_PROFILE_ID,
        "surface": "release_attestation",
        "mode": "environment_override",
        "description": "Environment-selected independent witness identity for non-synthetic release attestation.",
        "actorType": "independent_witness",
        "role": "independent_replay_witness",
        "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
        "identityId": "oc-live-release-witness",
        "fallbackIdentityId": "oc-synthetic-release-witness",
        "keyId": "",
        "publicKeyPath": "",
        "privateKeyPath": "",
        "environmentVariables": [
            RELEASE_WITNESS_MODE_ENV,
            RELEASE_WITNESS_ID_ENV,
        ],
        "syntheticFallbackAllowed": True,
        "notes": [
            "This profile becomes active when the release witness mode is set to live or a witness ID is supplied through the environment.",
            "The current release attestation is still unsigned metadata, so this profile governs identity disclosure rather than cryptographic witness signing.",
        ],
    },
)

TRUST_ROOT_PROFILE_BY_ID = {profile["profileId"]: profile for profile in TRUST_ROOT_PROFILES}


def build_public_trust_root_registry() -> dict[str, Any]:
    return {
        "registryVersion": "0.1.0",
        "profiles": list(TRUST_ROOT_PROFILES),
    }


def trust_root_profile(profile_id: str) -> dict[str, Any] | None:
    return TRUST_ROOT_PROFILE_BY_ID.get(profile_id)


def _env_has_all(env: Mapping[str, str], variable_names: tuple[str, ...]) -> bool:
    return all(env.get(name) for name in variable_names)


def resolve_release_signer(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = env or os.environ
    profile = trust_root_profile(ENV_RELEASE_SIGNER_PROFILE_ID)
    assert profile is not None
    if _env_has_all(env, (RELEASE_SIGNER_PRIVATE_KEY_ENV, RELEASE_SIGNER_PUBLIC_KEY_ENV)):
        signer = {
            "signerId": env.get(RELEASE_SIGNER_ID_ENV, "oc-live-release-signer"),
            "signerType": "verifier_service",
            "signerRole": env.get(RELEASE_SIGNER_ROLE_ENV, "release_signer"),
            "trustPolicyId": VERIFIER_SERVICE_POLICY_ID,
            "keyId": env.get(RELEASE_SIGNER_KEY_ID_ENV, "env-supplied"),
            "algorithm": "Ed25519",
            "publicKeyPath": "public-key.pem",
        }
        validate_registered_identity(
            signer["signerId"],
            surface="signed_artifact",
            actor_type=signer["signerType"],
            role=signer["signerRole"],
            trust_policy_id=signer["trustPolicyId"],
            key_id=signer["keyId"],
        )
        return {
            "profile": profile,
            "source": "environment_override",
            "signer": signer,
            "privateKeyPath": Path(env[RELEASE_SIGNER_PRIVATE_KEY_ENV]),
            "publicKeySourcePath": Path(env[RELEASE_SIGNER_PUBLIC_KEY_ENV]),
        }

    fallback = trust_root_profile(SYNTHETIC_RELEASE_SIGNER_PROFILE_ID)
    assert fallback is not None
    validate_registered_identity(
        SYNTHETIC_RELEASE_SIGNER["signerId"],
        surface="signed_artifact",
        actor_type=SYNTHETIC_RELEASE_SIGNER["signerType"],
        role=SYNTHETIC_RELEASE_SIGNER["signerRole"],
        trust_policy_id=SYNTHETIC_RELEASE_SIGNER["trustPolicyId"],
        key_id=SYNTHETIC_RELEASE_SIGNER["keyId"],
    )
    return {
        "profile": fallback,
        "source": "synthetic_reference",
        "signer": dict(SYNTHETIC_RELEASE_SIGNER),
        "privateKeyPath": Path(fallback["privateKeyPath"]),
        "publicKeySourcePath": Path("fixtures/public/signing/exampleco-synthetic-ed25519-public-key.pem"),
    }


def resolve_release_attestation_witness(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = env or os.environ
    use_live_profile = env.get(RELEASE_WITNESS_MODE_ENV) == "live" or bool(env.get(RELEASE_WITNESS_ID_ENV))
    if use_live_profile:
        profile = trust_root_profile(ENV_RELEASE_WITNESS_PROFILE_ID)
        assert profile is not None
        witness = {
            "witnessId": env.get(RELEASE_WITNESS_ID_ENV, "oc-live-release-witness"),
            "witnessType": "independent_witness",
            "witnessRole": env.get(RELEASE_WITNESS_ROLE_ENV, "independent_replay_witness"),
            "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
            "trustRootProfileId": profile["profileId"],
            "rootSource": "environment_override",
        }
        validate_registered_identity(
            witness["witnessId"],
            surface="release_attestation",
            actor_type=witness["witnessType"],
            role=witness["witnessRole"],
            trust_policy_id=witness["trustPolicyId"],
        )
        return witness

    profile = trust_root_profile(SYNTHETIC_RELEASE_WITNESS_PROFILE_ID)
    assert profile is not None
    witness = {
        "witnessId": "oc-synthetic-release-witness",
        "witnessType": "independent_witness",
        "witnessRole": "independent_replay_witness",
        "trustPolicyId": INDEPENDENT_WITNESS_POLICY_ID,
        "trustRootProfileId": profile["profileId"],
        "rootSource": "synthetic_reference",
    }
    validate_registered_identity(
        witness["witnessId"],
        surface="release_attestation",
        actor_type=witness["witnessType"],
        role=witness["witnessRole"],
        trust_policy_id=witness["trustPolicyId"],
    )
    return witness
