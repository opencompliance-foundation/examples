# Revocation

## Purpose

A revocation records that a previously published compliance artifact should no longer be relied on.

The revocation itself is a first-class artifact.

## Minimum required fields

- `revocationId`
- `artifactType`
- `artifactId`
- `revokedAt`
- `reason`

## Optional fields

- `supersededBy`
- `note`

## Rules

1. Revocations must be publishable independently of replacement artifacts.
2. A revocation should say what was revoked and why.
3. If a later artifact supersedes the revoked one, `supersededBy` should name it explicitly.
