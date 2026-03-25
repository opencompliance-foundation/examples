# ExampleCo Showcase

This directory is a public-safe meta-pack that shows how a hypothetical company
could use OpenCompliance to present scoped assurance artifacts honestly.

It does not pretend that ExampleCo is fully compliant with an entire framework.
It shows how one synthetic company can publish multiple corridor-specific
results and say, for each corridor:

- what is mechanically demonstrated,
- what depends on signed attestation,
- what still fails or blocks issuance,
- and what remains outside scope.

## Included source files

- `company.json`
- `showcase-config.json`

## Generated artifacts

- `showcase-report.json`
- `showcase-summary.md`

## Corridor set

- `../cyber-baseline/`
- `../issued/`
- `../ai-governance/`
- `../failed/`

## Intended use

- show buyers what ExampleCo can safely claim today,
- show auditors and reviewers the difference between proof, attestation, and
  blocked controls,
- show contributors how multiple corridor artifacts can be aggregated into one
  public assurance story,
- and provide a reusable synthetic model that others can adapt without leaking
  private company data.
