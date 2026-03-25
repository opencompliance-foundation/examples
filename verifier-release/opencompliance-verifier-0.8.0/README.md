# opencompliance-verifier-0.8.0

This is the first versioned OpenCompliance public verifier bundle for `opencompliance-verifier/0.8.0`.

It is a public, synthetic, replayable reference release.

Included:

- Python verifier runtime under `src/opencompliance/`
- Lean 4 proof corridor under `lean4-controls/`
- Open specs, schemas, and control boundaries under `open-specs/`
- Machine-readable verifier contract under `open-specs/verifier-contract.json`
- Evidence-claim schemas under `evidence-schema/`
- Conformance scripts and vectors under `conformance/`
- Synthetic ExampleCo fixtures under `fixtures/public/`
- Signed file manifest for the bundle under `signed-artifact-manifest.json`

Runnable public fixture roots:

- `minimal`, `failed`, `stale`, `medium`, `issued`, `cyber-baseline`, `ai-governance`

Example commands:

```bash
python3 scripts/verify_fixture.py --fixture-root fixtures/public/minimal --check
python3 scripts/run_lean_batch.py --fixture minimal
python3 conformance/scripts/validate_public_examples.py --fixture all
python3 scripts/verify_signed_artifacts.py --manifest signed-artifact-manifest.json --artifact-root .
```
