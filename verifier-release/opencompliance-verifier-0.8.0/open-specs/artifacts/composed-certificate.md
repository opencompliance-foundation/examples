# Composed Certificate

## Purpose

A composed certificate is a higher-level trust artifact built from narrower issued component certificates.

It is only valid when the component certificates all remain issued and their organisation and framework intent align.

## Minimum required fields

- `composedCertificateId`
- `status`
- `generatedAt`
- `organisation`
- `frameworkIntent`
- `scope`
- `componentCertificates`
- `controlRefs`
- `coverage`
- `compositionRule`

## Rules

1. Component certificates must all be `issued`.
2. Component certificates must belong to the same organisation.
3. Component certificates must share an identical framework intent.
4. Composition must preserve the control reference set and aggregated coverage of the children.
