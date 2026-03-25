# Contributing to OpenCompliance Evidence Schema

This repo holds machine-readable schemas for typed evidence claims.

## Ground rules

- Keep schema changes explicit and version-aware.
- Do not widen fields casually if it weakens verification semantics.
- Examples must validate against the published schema.
- Keep signer, provenance, and scope semantics readable to implementers.

## Before opening a PR

- Update the example file if the schema changes.
- Explain compatibility impact.
- Avoid optional fields that collapse distinct concepts into one bucket.
- Keep the format usable for public fixtures without leaking private conventions.
