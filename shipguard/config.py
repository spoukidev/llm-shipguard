"""Policy model loaded from YAML (``config/policy.yaml``).

The policy is *trusted* configuration: it is written by the operator,
never by end users. Every field has a safe default so an empty YAML file
still produces a working, conservative gateway.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"


class UpstreamConfig(BaseModel):
    type: Literal["mock", "openai", "anthropic"] = "mock"
    base_url: str | None = None
    api_key_env: str | None = None          # name of env var holding the provider key
    timeout_s: float = 60.0
    model_override: str | None = None       # rewrite the model name sent upstream
    extra_headers: dict[str, str] = Field(default_factory=dict)


class RoutingConfig(BaseModel):
    default_upstream: str = "mock"
    # "openai/gpt-4o-mini" -> upstream "openai", model "gpt-4o-mini"
    model_prefixes: dict[str, str] = Field(default_factory=dict)


class InjectionThresholds(BaseModel):
    warn_at: float = 0.4
    block_at: float = 0.7


class DocumentThresholds(BaseModel):
    quarantine_at: float = 0.45
    action: Literal["quarantine", "block", "warn"] = "quarantine"


class InjectionConfig(BaseModel):
    enabled: bool = True
    user: InjectionThresholds = Field(default_factory=InjectionThresholds)
    documents: DocumentThresholds = Field(default_factory=DocumentThresholds)
    decode_payloads: bool = True            # base64 / hex / rot13 / leetspeak re-scan
    classifier_enabled: bool = False        # optional transformers model (not required)
    classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    classifier_weight: float = 0.6


class UnicodeConfig(BaseModel):
    enabled: bool = True
    strip_invisible: bool = True            # zero-width, bidi controls, tag characters
    fold_homoglyphs: bool = True            # map Cyrillic/Greek look-alikes inside Latin words


class RedactionConfig(BaseModel):
    action: Literal["redact", "block", "warn", "off"] = "redact"
    restore_in_output: bool = False


class PIIConfig(RedactionConfig):
    restore_in_output: bool = True
    engine: Literal["regex", "presidio"] = "regex"
    entities: list[str] = Field(
        default_factory=lambda: ["EMAIL", "PHONE", "CREDIT_CARD", "US_SSN", "IBAN"]
    )


class SpotlightConfig(BaseModel):
    mode: Literal["delimit", "datamark", "off"] = "delimit"
    document_tags: list[str] = Field(default_factory=lambda: ["document", "retrieved", "context"])
    treat_tool_messages_as_documents: bool = True


class InputConfig(BaseModel):
    max_prompt_chars: int = 32_000
    max_messages: int = 64
    max_tokens_cap: int = 2048
    unicode: UnicodeConfig = Field(default_factory=UnicodeConfig)
    secrets: RedactionConfig = Field(default_factory=RedactionConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    injection: InjectionConfig = Field(default_factory=InjectionConfig)
    spotlight: SpotlightConfig = Field(default_factory=SpotlightConfig)


class CanaryConfig(BaseModel):
    enabled: bool = True
    action: Literal["block", "warn"] = "block"
    prefix: str = "SG-CANARY"


class TopicRule(BaseModel):
    name: str
    patterns: list[str]
    scan_input: bool = True
    scan_output: bool = True


class OutputConfig(BaseModel):
    system_prompt_overlap_words: int = 10    # verbatim run length that counts as a leak
    blocked_markers: list[str] = Field(default_factory=list)
    disallowed_topics: list[TopicRule] = Field(default_factory=list)
    link_allowed_hosts: list[str] = Field(default_factory=list)
    link_action: Literal["strip", "block", "warn"] = "strip"
    scan_secrets: bool = True
    scan_pii: bool = True


class ToolRule(BaseModel):
    allowed_recipient_domains: list[str] | None = None
    allowed_hosts: list[str] | None = None
    max_calls: int | None = None


class ToolsConfig(BaseModel):
    enabled: bool = True
    allowed: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    rules: dict[str, ToolRule] = Field(default_factory=dict)
    max_tool_calls: int = 4


class RateLimit(BaseModel):
    requests_per_minute: float = 60
    burst: int = 20


class RateLimitConfig(BaseModel):
    enabled: bool = True
    default: RateLimit = Field(default_factory=RateLimit)
    routes: dict[str, RateLimit] = Field(default_factory=dict)


class AuditConfig(BaseModel):
    enabled: bool = True
    db_url: str = "sqlite:///./data/audit.db"
    store_redacted_preview: bool = True
    preview_chars: int = 160


class ServerConfig(BaseModel):
    on_block: Literal["completion", "error"] = "completion"
    expose_decision_in_body: bool = True
    block_message: str = "This request was blocked by ShipGuard security policy."


class Policy(BaseModel):
    version: int = 1
    upstreams: dict[str, UpstreamConfig] = Field(
        default_factory=lambda: {"mock": UpstreamConfig(type="mock")}
    )
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    input: InputConfig = Field(default_factory=InputConfig)
    canary: CanaryConfig = Field(default_factory=CanaryConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)


_ENV_DEFAULT = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}")


def _expand_env(text: str) -> str:
    """Expand ``${VAR}`` and ``${VAR:-default}``."""
    text = _ENV_DEFAULT.sub(lambda m: os.environ.get(m.group(1)) or m.group(2), text)
    return os.path.expandvars(text)


def load_policy(path: str | os.PathLike | None = None) -> Policy:
    """Load a policy from YAML. ``SHIPGUARD_POLICY`` overrides the default path."""
    p = Path(path or os.environ.get("SHIPGUARD_POLICY") or DEFAULT_POLICY_PATH)
    if not p.exists():
        return Policy()
    raw = yaml.safe_load(_expand_env(p.read_text(encoding="utf-8"))) or {}
    policy = Policy.model_validate(raw)
    db_env = os.environ.get("SHIPGUARD_AUDIT_DB")
    if db_env:
        policy.audit.db_url = db_env
    return policy
