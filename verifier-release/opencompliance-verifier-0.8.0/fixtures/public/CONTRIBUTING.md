# Contributing to OpenCompliance Public Examples

This repo holds public-safe synthetic example bundles.

## Ground rules

- Never add customer data, secrets, or realistic production identifiers.
- Keep fixtures small enough to inspect manually.
- When a fixture changes, update any published digests and conformance vectors that depend on it.
- Prefer one sharp example over many fuzzy ones.

## Before opening a PR

- Explain what the fixture is demonstrating.
- Keep the artifact set internally consistent.
- Recompute witness or hash expectations if any referenced artifact changes.
- Say clearly whether a field is meant to be runtime-proof material, attestation material, or judgment material.
