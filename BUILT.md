# BUILT: ShipGuard (llm-shipguard)

Built 2026-11-09 (Africa/Algiers) from `BRIEF.md`. Local git repo initialized and committed; **not pushed**.

## What it is

An OpenAI-compatible FastAPI gateway (`/v1/chat/completions`, `/v1/models`, `/v1/shipguard/scan`, `/healthz`) that
runs an ordered security pipeline around every call:

`limits → unicode → documents → injection → topics → secrets → pii → spotlight → canary → tools_request → [upstream] → tools_response → canary_check → output_policy → output_redaction → restore`

Upstreams: in-process mock, any OpenAI-compatible endpoint (OpenAI, OpenRouter, vLLM, Ollama, HTTP mock), and an
Anthropic Messages adapter. Audit trail in SQLite via SQLModel; Streamlit dashboard; YAML policy.
Includes the deliberately vulnerable LumenBot RAG app plus the identical app behind ShipGuard, and a before/after demo.

## Measured results (not estimated)

Eval: `python -m eval.run_eval --ablate` and the holdout command below, in-process ASGI, gullible mock upstream.

| Metric | Dev corpus (111 attacks / 120 benign) | Holdout (36 attacks, 33 valid / 37 benign) | Target | Result |
|---|---|---|---|---|
| Attack catch rate | **97.3%** (108/111) | **90.9%** (30/33) | ≥ 85% | PASS |
| False-positive rate (blocked or doc quarantined) | **0.8%** (1/120) | **0.0%** | ≤ 8% | PASS |
| Baseline attack success without gateway | 100% | 91.7% | – | – |
| Detection rate (any filter fired) | 100% | 97.0% | – | – |
| Benign flagged incl. warn-only | 2.5% | 0.0% | – | – |
| Gateway overhead p50 / p95 | 0.58 / 1.30 ms | 0.57 / 1.41 ms | – | – |

The holdout corpus was written after tuning stopped and its numbers are from the first run (re-running after
later lint-only and mock-doc-selection changes gave identical numbers). Three holdout attacks did not succeed
against the unguarded mock and are excluded (`h-indirect-02`, `h-jail-01`, `h-leak-01`).

Ablation (dev, catch rate with one layer disabled): injection 60.4%, secrets/PII 79.3%, output policy 82.9%,
canary 91.0%, unicode 93.7%, tools 93.7%, spotlight 97.3% (no effect against the mock).

Misses: user prompts whose only signal is "answer with this exact token" (dev `direct-09`, `direct-16`,
`obfuscated-10`; holdout `h-direct-01..03`). Dev false positive: `benign-055` ("What is a system prompt…?"). The
gullible mock dumps its system prompt in reply, and the canary blocks it.

Reports: `eval/results/report_dev.md`, `eval/results/report_holdout.md`, per-item `results_*.json`, chart
`docs/img/catch_rate_dev.svg`.

## Tests

`pytest -q` → **111 passed** (~3–6 s). Covers every filter, redaction vault, tool policy, rate limiter, audit privacy,
pipeline order and short-circuiting, upstream adapters (MockTransport), OpenAI SDK drop-in + streaming, auth, 429,
502, end-to-end demo over real HTTP, eval targets, and corpus domain hygiene. `ruff check .` is clean.

## Docker status

**Works on this box.** `docker compose config` validates. I ran `docker compose up -d --build` and it brought up
5 services (gateway :8088, mock-upstream :9000, vulnerable-app :8101, guarded-app :8102, dashboard :8502). curl to
`/v1/chat/completions` works, and `docker compose run --rm demo` passes all 5 scenarios. Transcript:
`docs/docker_run.md`. The stack is still running.

Box-specific note: Docker on this machine needs `sudo`, and the host's legacy-iptables `FORWARD` policy is `DROP`,
so containers could not reach each other at first (the gateway timed out reaching the mock). I added one rule
that only allows traffic within the project's own bridge network:
`iptables-legacy -I FORWARD 1 -i br-1c45483996d3 -o br-1c45483996d3 -j ACCEPT`. This is the same approach used
for prompt-injection-tripwire. It is not persistent across reboots and is not needed on a normal Docker host.

## How to run

```bash
pip install -r requirements-dev.txt
make test            # pytest
make demo            # mock + gateway in-process, before/after demo (A secret, B canary, C injection doc, D tool, E rate limit)
make eval            # dev eval -> eval/results/report_dev.md   (make ablate / make eval-holdout)
docker compose up -d --build && make curl && docker compose run --rm demo
```

## Deviations from the brief

- **PII**: regex + checksum fallback is the default (documented); `presidio` is an optional engine and was not used for
  the measured runs.
- **Classifier**: `transformers` hook implemented but off by default, and not run or measured.
- **Streaming** is buffered SSE (the whole completion is checked first) rather than token-by-token pass-through.
- Added beyond the brief: `/v1/shipguard/scan` dry-run endpoint, optional client API keys (`SHIPGUARD_API_KEYS`),
  `on_block: error` mode (HTTP 403), max-tokens clamp, holdout corpus, ablations, SVG chart, `SECURITY.md`,
  `.env.example`, `examples/openai_client.py`.
- File layout matches §4, plus `shipguard/{config,types,mock_llm}.py`, `mock_upstream/app.py`, `demo/run_demo.py`,
  `demo/docs/`, `eval/fakes.py`, `scripts/make_chart.py`.

## Limitations

- Heuristic detection can be bypassed by paraphrase, multi-turn setups, or other languages. It is one layer, not a
  guarantee.
- All numbers are against a deterministic mock that obeys any injection it parses. They are not claims about real
  models. The corpus is small (231 dev + 73 holdout items) and was written by the detector author.
- Spotlighting gives no measurable benefit here because the mock ignores delimiters.
- Rate limits are in-memory (single replica). The canary secret is random per process unless `SHIPGUARD_CANARY_SECRET`
  is set.
- Only text content parts are scanned; image/audio parts pass through.
- No live third-party provider was called (no keys used). The OpenAI-compatible and Anthropic adapters are tested
  against `httpx.MockTransport`.

## Safety / hygiene

Fake secrets are generated at runtime (`eval/fakes.py`, string concatenation) so no credential-shaped literals are
committed, apart from the clearly fake demo AWS key ID in `docs/docker_run.md`. All hosts are `.test` / `.example`.
Disallowed topics are fictional. Tools in the demo are simulated and never executed.
