# API design — OpenAPI specification

[`openapi.yaml`](../../openapi.yaml) (repo root) is the **scoring contract source of truth**
for the deployed service. It documents the FDEBench endpoints — `GET /health`,
`POST /triage`, `POST /extract`, `POST /orchestrate` — with their exact
request/response schemas, enum vocabularies, response headers, error envelopes,
and worked examples. The live app also exposes operational endpoints
`/metrics`, `/metrics.json`, and `/dashboard`; those are documented in
[`docs/architecture.md`](../architecture.md).

## How to view it

- **Swagger Editor** — paste the file at <https://editor.swagger.io>.
- **Redocly** — `npx @redocly/cli preview-docs openapi.yaml`.
- **VS Code** — the *OpenAPI (Swagger) Editor* or *Redoc Preview* extensions render it inline.
- **Live app** — once running, FastAPI also serves interactive docs at `/docs` and the
  generated schema at `/openapi.json`.

## Validate it

```bash
pip install openapi-spec-validator pyyaml
python -c "from openapi_spec_validator import validate_spec; import yaml; validate_spec(yaml.safe_load(open('openapi.yaml')))"
```

## What this captures (design intent)

- **Enum-only routable fields** — `Category`, `Priority`, `Team`, and `MissingInfo` are closed
  vocabularies so downstream automation never parses prose.
- **Judgment over loudness** — the `/triage` examples contrast a calm senior-officer signal that
  resolves to **P1** against a shouty "URGENT!!!" coffee-machine signal that resolves to **P4**.
- **Hard escalations** — hull breach, atmospheric compromise, and restricted-zone/containment
  access always escalate (enforced server-side, not by the model alone).
- **Observability** — every success returns `X-Model-Name`, `X-Latency-Ms`, and `X-Request-Id`;
  the deployed app also exposes Prometheus metrics and a lightweight live dashboard.
- **Honest failure modes** — `400` for malformed/empty/wrong-content-type bodies, `422` for
  schema-invalid input; valid-but-degraded requests still return a complete `200` envelope.

This spec is kept in sync with the implementation as the endpoints are built out.
