# Signed Artifact Manifest

## Purpose

A signed-artifact manifest binds canonical OpenCompliance artifacts to a signer identity and public key.

It is the bridge between canonical digests and identity-bound trust.

## Minimum required fields

- `signatureBundleId`
- `generatedAt`
- `signer`
- `artifacts`

## Rules

1. Each signature is over the canonical bytes of the referenced artifact, not over a rendered or reformatted copy.
2. The manifest must disclose the signer ID, key ID, algorithm, and public key path used for verification.
3. Digest mismatch or signature failure invalidates the signed manifest.
4. Public examples may use synthetic keys, but that fact must be disclosed clearly.
