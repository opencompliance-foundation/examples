# Verifier Release Manifest

The verifier release manifest describes a versioned, replayable OpenCompliance verifier bundle.

It is not a claim about framework compliance on its own. It is a packaging contract for the public runtime, Lean corridor, public schemas, conformance checks, and synthetic example fixtures that a third party can rerun outside the private working monorepo.

## Required Fields

- `$schema`
- `releaseId`
- `verifierVersion`
- `generatedAt`
- `bundleLayoutVersion`
- `entrypoints`
- `includedFixtures`
- `includedRoots`
- `signedArtifactManifestPath`

## Purpose

The release manifest should let an external reviewer answer:

- which verifier version they are running,
- which fixtures and public roots are included,
- which scripts are the supported entrypoints,
- and where the signed file-manifest for the bundle lives.

## Boundary

The release bundle is still a synthetic public reference release.

It demonstrates:

- deterministic artifact generation,
- Lean-backed proof replay,
- typed runtime verdict replay,
- signature-manifest verification,
- and fixture-level conformance validation.

It does not claim that the whole bundle is a production distribution pipeline or an official audit opinion.
