# Contributing to OpenCompliance Lean4 Controls

This repo holds the public Lean 4 control corridor.

## Ground rules

- Formalize only narrow, decidable claims that can be defended from explicit evidence.
- Keep proofs separate from attestations and human judgment.
- Name the proof boundary directly when a theorem is narrower than the surrounding control family.
- Avoid importing complexity that is not needed for the current corridor.

## Before opening a PR

- Keep the theorem set aligned with the public example bundle.
- Update boundary notes if a theorem changes meaning.
- Run `lake build`.
- Do not imply that a theorem proves framework-wide compliance when it only proves a scoped predicate.
