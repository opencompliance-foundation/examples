# Inclusion Proofs

## Purpose

Inclusion proofs let a third party verify that each logged artifact leaf is included in a published transparency root.

## Minimum required fields

- `bundleId`
- `rootHash`
- `proofs`

## Proof item rules

Each proof item must include:

- `path`
- `leafHash`
- `proof`

Each proof step must include:

- `position`
- `hash`

## Rules

1. Every published transparency-log entry should have a matching inclusion proof.
2. Proof verification should succeed against the published `rootHash`.
3. A proof mismatch is a verification failure, not an informational warning.
4. Inclusion proofs should be publishable without access to private source material.
