# Replay Bundle

## Purpose

A replay bundle pins the material inputs and expected outputs for a deterministic verification rerun.

It is the bridge between a hosted verification claim and an independently rerunnable check.

## Minimum required fields

- `replayBundleId`
- `generatedAt`
- `bundleId`
- `verifierVersion`
- `fixture` or equivalent scope identifier
- `replayCommand`
- `materialInputs`
- `expectedOutputs`

## Artifact entry

Each `materialInputs` or `expectedOutputs` entry should include:

- `artifactType`
- `path`
- `sha256`

## Rules

1. The replay bundle must pin the inputs that materially determine the rerun.
2. The replay bundle must pin the outputs that the witness is expected to match exactly.
3. The replay bundle must not include its own digest as an expected output because that creates recursion.
4. Replay mismatches are verification failures, not warnings.
