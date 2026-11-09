# Security policy

ShipGuard is an **educational / defensive** project. It is a layer of defense, not a guarantee:
heuristic detectors can be bypassed, and the measured numbers come from a small synthetic corpus
against a mock model.

## Reporting a vulnerability

Please open a private security advisory on the repository (GitHub → Security → Advisories) rather
than a public issue. Include a minimal reproduction using fake data only.

## Ground rules for contributions

- Never commit real secrets, tokens, or personal data. Tests and the corpus generate fake,
  pattern-shaped values at runtime (`eval/fakes.py`).
- Use reserved domains only (`.test`, `.example`, `.invalid`) in payloads and fixtures.
- Disallowed-content categories in the corpus are fictional (e.g. "Glimmer Device").
- Do not point the eval harness or demo at third-party systems you do not own.

## Deployment notes

- Set `SHIPGUARD_CANARY_SECRET` and `SHIPGUARD_API_KEYS` in production.
- Provider API keys belong only in the gateway's environment; ShipGuard never forwards the
  client's `Authorization` header upstream.
- The mock upstream (`mock_upstream/`) is intentionally vulnerable. Never expose it publicly.
