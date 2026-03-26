# Verify Workbench

This is a local browser workbench for the OpenCompliance Verify API.

It is meant to be served from a local checkout of this repository while the
local API is running on `127.0.0.1:8788`. The same `ui/verify/` directory is
also shipped inside the versioned public verifier release bundle.

## Quickstart

From `projects/dev/opencompliance`:

```sh
python3 scripts/serve_verify_api.py --port 8788
```

In a second terminal:

```sh
python3 -m http.server 8000
```

Then open:

```text
http://127.0.0.1:8000/ui/verify/
```

## What it does

- load a synthetic ExampleCo inline bundle from `fixtures/public/*`
- load any current public synthetic fixture selected in the fixture dropdown
- submit either `inline_bundle` or `fixture_path` requests
- call `GET /contract` against the local API
- show the returned outcome, summary, and raw JSON response

## Boundary

This is a local workbench, not a production frontend.

It exists to make the current deterministic Verify surface inspectable without
pretending there is already a complete hosted workspace or multi-tenant product
UI.
