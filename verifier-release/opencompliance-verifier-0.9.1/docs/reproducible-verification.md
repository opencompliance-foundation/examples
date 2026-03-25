# Reproducible Verification

## Current contract

Each synthetic fixture now emits a `replay-bundle.json`.

The replay bundle pins:

- the material input digests,
- the expected output digests,
- the verifier version string,
- and the reference replay command.

## What exact-match means

The witness receipt is only valid when the replayed artifact digests exactly match the replay bundle.

Digest mismatches are failures.

They do not degrade to warnings.

## Current limitation

The replay bundle is strong enough to exercise the public-safe synthetic corridor, but it does not yet pin a published verifier source release.

That means the current replay model is serious for internal development and public examples, but not yet a full external release discipline.
