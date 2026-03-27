# Classification Model

## Current routes

OpenCompliance keeps three leaf routes in the current public corridor:

- `decidable`
- `attestation`
- `judgment`

It also publishes `mixedControls` when one higher-level control decomposes into more than one of those leaf routes.

## Current meaning

- `decidable` means the corridor expects typed machine evidence and can evaluate a narrow predicate deterministically.
- `attestation` means the corridor expects a signed human statement with scope and freshness, not a theorem over system state.
- `judgment` means the corridor is intentionally left for human review and should never be flattened into a fake machine proof.

## Current public artifact

Each synthetic ExampleCo pack now includes `classification-result.json`.

That file persists:

- the route for each claim,
- the expected claim type if evidence is required,
- whether the current public control boundary has Lean backing,
- and the rationale for the route choice.

The medium pack now also includes a first public `mixedControls` section.

That section groups repo policy, CI policy, and signed change-review governance evidence under one mixed change-control boundary while keeping the leaf claims explicit.

## Current limitation

The current mixed-control format is still narrow and synthetic.

It proves the artifact shape, not a general ontology for every kind of decomposition the real product will eventually need.
