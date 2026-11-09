# ShipGuard: A Secure LLM Gateway for Production-Style Deployments

**Slug:** `llm-shipguard`  
**Level:** Intermediate  
**Estimated effort:** 2–3 weeks part time  
**Why it ships well on GitHub:** Looks like something a security-minded backend engineer would actually deploy: a proxy, policies, tests, and an audit log.

## 1. Goal

Build an **OpenAI-compatible HTTP gateway** that sits in front of any chat-completions API (OpenAI, Anthropic via a small adapter, vLLM, Ollama, OpenRouter). Before and after each call it applies security controls:

- Secret and PII detection / redaction on inputs and outputs
- Prompt-injection and jailbreak heuristics on untrusted content
- Output policy checks (e.g. block leaking a planted system-prompt canary)
- Per-route rate limits, tool-call allowlists, and a structured audit trail

Ship a deliberately thin “vulnerable app” *and* the same app behind ShipGuard so a demo script shows blocked vs allowed requests.

## 2. Threat model

| Item | Description |
|---|---|
| **Asset** | User PII and secrets in prompts; system prompt; downstream tool actions; the provider API key |
| **Attacker** | End user of an app that forwards their text (and retrieved docs) to an LLM |
| **Attacker goals** | Leak the system prompt; exfiltrate secrets that appeared in context; jailbreak into disallowed categories; trigger dangerous tool calls; abuse cost via flooding |
| **Trust boundary** | Gateway config, system prompt, and allowlists are trusted. User messages and retrieved documents are not |
| **Out of scope** | Breaking the upstream model provider; training-time attacks; protecting against a fully compromised host |

## 3. Tech stack

- Python 3.11+, **FastAPI**, Pydantic, httpx
- Detection: `presidio-analyzer` / `presidio-anonymizer` (or a small regex+NER fallback) for PII; custom secret regexes (AWS keys, PEM, Slack tokens — pattern only)
- Injection / jailbreak: layered heuristics (instruction-like phrases, hidden unicode, encoded payloads) plus an optional small classifier (`transformers`)
- Storage: SQLite via SQLModel for audit logs
- Config: YAML policies
- Tests: pytest + httpx ASGI client
- Docker Compose: gateway + mock upstream LLM + demo app
- Optional dashboard: Streamlit reading the audit DB

## 4. Key components / structure

```
llm-shipguard/
├── BRIEF.md
├── README.md                   # architecture diagram + before/after demo
├── docker-compose.yml
├── pyproject.toml
├── config/policy.yaml
├── shipguard/
│   ├── server.py               # OpenAI-compatible /v1/chat/completions
│   ├── upstream.py             # fan-out to real or mock providers
│   ├── pipeline.py             # ordered middleware
│   ├── filters/
│   │   ├── pii.py
│   │   ├── secrets.py
│   │   ├── injection.py
│   │   ├── canary.py           # system-prompt canary in/out
│   │   ├── unicode.py          # zero-width / homoglyphs
│   │   └── output_policy.py
│   ├── tools_policy.py         # allow / deny tool names and URL hosts
│   ├── ratelimit.py
│   ├── audit.py
│   └── redact.py               # consistent placeholder tokens
├── demo/
│   ├── vulnerable_app.py       # naive RAG chatbot (local docs only)
│   └── guarded_app.py          # same app pointed at ShipGuard
├── eval/
│   ├── corpus/                 # benign + attack prompts (educational)
│   └── run_eval.py             # precision/recall of blocks vs utility
├── tests/
└── dashboard/app.py
```

## 5. Key features

1. **Drop-in proxy:** point `OPENAI_BASE_URL` at ShipGuard; existing OpenAI clients keep working.
2. **Bidirectional redaction:** mask secrets/PII going *to* the model and *from* the model; restore placeholders on the way back when policy allows.
3. **System-prompt canary:** inject a per-session token into the system prompt; block or warn if it appears in the completion.
4. **Untrusted-document wrapping:** optional “spotlighting” / delimiters around retrieved context plus injection heuristics.
5. **Tool allowlist:** if the upstream response contains tool calls, drop unknown tools or disallowed hosts.
6. **Audit log:** hashed/redacted request metadata, which filter fired, latency, decision.
7. **Eval harness:** measure false-positive rate on benign chat and catch rate on a labeled attack corpus.

## 6. Success criteria

- `docker compose up` + a curl against `/v1/chat/completions` works with a mock upstream (no paid API required for CI).
- Demo script shows: (a) secret in a user prompt is redacted before upstream sees it; (b) canary leak is blocked; (c) an injection-style retrieved doc does not produce `INJECTION_SUCCESS` through the guarded app.
- Eval report: attack catch rate ≥ 85% on the included corpus and false-positive rate ≤ 8% on benign chats.
- pytest covers each filter and the pipeline order.
- README includes an architecture sketch, policy examples, and ethical-use notes.

## 7. Why it's good for a skills profile

Secure *deployment* is what many AI-security roles actually do day to day. This repo shows API design, policy engines, testing, and Docker — not only notebooks. It pairs well with red-team projects: one repo attacks models, this one shows you can put a control plane in front of them.
