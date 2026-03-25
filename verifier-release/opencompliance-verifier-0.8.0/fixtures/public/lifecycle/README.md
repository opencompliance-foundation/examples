# ExampleCo Lifecycle Pack

This directory is a synthetic public-safe lifecycle example for OpenCompliance.

It demonstrates two things that sit beyond the basic Verify flow:

- fail-closed drift handling for an already-issued certificate, and
- composition of smaller component certificates into a higher-level artifact.

## Files

- `issued-source-change.json`: a normalized source-change event affecting the previously issued corridor.
- `issued-lifecycle-reverification-required.json`: lifecycle decision that marks the certificate stale until rerun.
- `issued-lifecycle-revoked.json`: fail-closed lifecycle decision that revokes the certificate immediately.
- `component-identity-certificate.json`: synthetic issued component certificate for identity and logging.
- `component-identity-profile.json`: matching scope/profile metadata for the identity component.
- `component-recovery-certificate.json`: synthetic issued component certificate for training and recovery.
- `component-recovery-profile.json`: matching scope/profile metadata for the recovery component.
- `compose-manifest.json`: manifest consumed by `scripts/compose_certificates.py`.
- `composed-agent-certificate.json`: composed higher-level certificate built from the two component certificates.

## Rule

This pack is synthetic and narrow.

It exists to demonstrate lifecycle semantics, not to pretend that OpenCompliance already has a full continuous-verification production system.
