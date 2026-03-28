# opencompliance-verifier-0.9.6

This is the first versioned OpenCompliance public verifier bundle for `opencompliance-verifier/0.9.6`.

It is a public, synthetic, replayable reference release.

Included:

- Python verifier runtime under `src/opencompliance/`
- Lean 4 proof corridor under `lean4-controls/`
- Open specs, schemas, and control boundaries under `open-specs/`
- Machine-readable verifier contract under `open-specs/verifier-contract.json`
- Release attestation under `release-attestation.json`
- Evidence-claim schemas under `evidence-schema/`
- Conformance scripts and vectors under `conformance/`
- Static docs under `docs/` and the local Verify workbench under `ui/verify/`
- Synthetic ExampleCo fixtures under `fixtures/public/`
- Signed file manifest for the bundle under `signed-artifact-manifest.json`

Runnable public fixture roots:

- `minimal`, `failed`, `stale`, `medium`, `issued`, `cyber-baseline`, `ai-governance`

Example commands:

```bash
python3 scripts/verify_fixture.py --fixture-root fixtures/public/minimal --check
python3 scripts/serve_verify_api.py --port 8788
python3 -m http.server 8000
python3 scripts/run_lean_batch.py --fixture minimal
python3 scripts/attest_release_bundle.py --bundle-root . --check
python3 conformance/scripts/validate_public_examples.py --fixture all
python3 scripts/verify_signed_artifacts.py --manifest signed-artifact-manifest.json --artifact-root .
```

Then open `http://127.0.0.1:8000/ui/verify/` for the local browser workbench.
