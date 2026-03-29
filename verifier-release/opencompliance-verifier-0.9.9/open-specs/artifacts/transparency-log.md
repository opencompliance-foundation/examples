# Transparency Log

## Purpose

A transparency log records the canonical digests of the main published artifacts for one verification bundle in append order.

It exists to make mutation visible.

## Minimum required fields

- `logId`
- `generatedAt`
- `bundleId`
- `hashAlgorithm`
- `rootHash`
- `entries`

## Entry rules

Each entry must include:

- `index`
- `artifactType`
- `path`
- `artifactSha256`
- `leafHash`

## Rules

1. Entry order is part of the log identity and must not be rewritten silently.
2. `artifactSha256` must be computed from the canonical artifact bytes.
3. `leafHash` must be derived from the entry fields without the `leafHash` itself.
4. `rootHash` must be reproducible from the ordered leaf hashes.
5. Replacements require a new append event, not in-place mutation of an old log.
