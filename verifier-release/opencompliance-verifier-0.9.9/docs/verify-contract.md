# Verify Contract

## Current deterministic reference surface

The current reference entrypoints are:

```sh
cd projects/dev/opencompliance
python3 scripts/verify_fixture.py --fixture-root fixtures/public/issued --check
```

```sh
cd projects/dev/opencompliance
python3 scripts/serve_verify_api.py --port 8788
```

The same surface now has a minimal local browser workbench:

```sh
cd projects/dev/opencompliance
python3 -m http.server 8000
```

Then open `http://127.0.0.1:8000/ui/verify/`.

The compatibility wrapper still exists for the built-in ExampleCo packs:

```sh
cd projects/dev/opencompliance
python3 scripts/verify_example.py --fixture issued --check
```

## API routes

The local HTTP surface now exposes:

- `GET /healthz`
- `GET /fixtures`
- `GET /contract`
- `POST /verify`

`POST /verify` accepts one of two request modes:

1. `fixture_path`

```json
{
  "fixtureName": "issued",
  "input": {
    "mode": "fixture_path",
    "fixtureRoot": "/abs/path/to/fixture-shaped-root"
  }
}
```

2. `inline_bundle`

```json
{
  "fixtureName": "issued",
  "input": {
    "mode": "inline_bundle",
    "profile": {"profileId": "exampleco-issued-profile"},
    "evidenceClaims": [],
    "useDefaultOscalSeed": true
  }
}
```

The inline bundle can also carry explicit OSCAL material under `input.oscal`
with `catalog`, `profile`, `ssp`, and `mappingCollection`. If `input.oscal`
is omitted, the current local API can fall back to the checked-in OSCAL seed
for the selected fixture when `useDefaultOscalSeed` is true.

## Inputs

The current deterministic corridor uses:

- `profile.json`
- `evidence-claims.json`
- the matching OSCAL catalog, profile, SSP, and mapping files under `oscal/`

## Deterministic outputs

Every run emits:

- `proof-bundle.json`
- `trust-surface-report.md`
- `verification-result.json`
- `replay-bundle.json`
- `witness-receipt.json`
- `revocation.json`

The outcome artifact depends on the proof summary:

- `certificate.json` when there are zero `judgmentRequired` and zero `evidenceMissing`
- `punch-list.json` otherwise

## Current boundary

This is still a synthetic reference surface.

It is useful for:

- validating the artifact contract,
- testing blocked and successful runs,
- checking fixture-shaped inputs by path instead of only by built-in example name,
- and exercising replay and transparency logic.

It is now a stable local HTTP/JSON API and local CLI surface for the synthetic
reference corridor, and a local browser workbench now exists for that same API,
but it is still not a general live-evidence network API.

Current limitations:

- the API is intentionally local-only and unauthenticated;
- the request model still depends on known fixture names and corridor shapes;
- inline bundles can reuse checked-in OSCAL seed material instead of carrying a
  fully explicit external control package;
- live connectors and signer-bound ingress remain future work.
