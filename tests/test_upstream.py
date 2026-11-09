"""Provider adapters, tested against httpx.MockTransport (no network)."""

import json

import httpx

from shipguard.config import UpstreamConfig
from shipguard.upstream import AnthropicUpstream, OpenAICompatibleUpstream, from_anthropic, to_anthropic


async def test_openai_compatible_forwards_and_uses_gateway_key(monkeypatch):
    monkeypatch.setenv("PROVIDER_KEY", "provider-secret")
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                                                      "finish_reason": "stop"}]})

    up = OpenAICompatibleUpstream("vllm", UpstreamConfig(type="openai", base_url="http://vllm.test/v1",
                                                         api_key_env="PROVIDER_KEY"),
                                  client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    r = await up.complete({"model": "m", "messages": [], "shipguard": {"x": 1}, "stream": True})
    assert seen["url"] == "http://vllm.test/v1/chat/completions" and seen["auth"] == "Bearer provider-secret"
    assert "shipguard" not in seen["body"] and "stream" not in seen["body"]
    assert r["choices"][0]["message"]["content"] == "hi"


def test_anthropic_translation_roundtrip():
    body = {"model": "claude-x", "max_tokens": 100, "stop": "END",
            "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"},
                         {"role": "assistant", "content": "", "tool_calls": [
                             {"id": "t1", "type": "function", "function": {"name": "search_docs", "arguments": '{"q": "a"}'}}]},
                         {"role": "tool", "tool_call_id": "t1", "content": "result"}],
            "tools": [{"type": "function", "function": {"name": "search_docs", "parameters": {"type": "object"}}}]}
    a = to_anthropic(body)
    assert a["system"] == "sys" and a["stop_sequences"] == ["END"] and a["tools"][0]["name"] == "search_docs"
    assert a["messages"][1]["content"][0]["type"] == "tool_use" and a["messages"][2]["content"][0]["type"] == "tool_result"
    o = from_anthropic({"id": "m1", "content": [{"type": "text", "text": "ok"},
                                                {"type": "tool_use", "id": "t2", "name": "get_weather", "input": {"c": "x"}}],
                        "stop_reason": "tool_use", "usage": {"input_tokens": 3, "output_tokens": 2}}, "claude-x")
    assert o["choices"][0]["finish_reason"] == "tool_calls" and o["usage"]["total_tokens"] == 5
    assert json.loads(o["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]) == {"c": "x"}


async def test_anthropic_upstream_http(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak")

    def handler(req: httpx.Request):
        assert req.url.path == "/v1/messages" and req.headers["x-api-key"] == "ak"
        return httpx.Response(200, json={"content": [{"type": "text", "text": "hello"}], "stop_reason": "end_turn"})

    up = AnthropicUpstream("anthropic", UpstreamConfig(type="anthropic", base_url="http://anthropic.test",
                                                       api_key_env="ANTHROPIC_API_KEY"),
                           client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    r = await up.complete({"model": "claude-x", "messages": [{"role": "user", "content": "hi"}]})
    assert r["choices"][0]["message"]["content"] == "hello"


async def test_gateway_does_not_forward_client_authorization(policy, audit):
    from shipguard.server import create_app

    seen = {}

    def handler(req: httpx.Request):
        seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "content": "x"},
                                                      "finish_reason": "stop"}]})

    up = OpenAICompatibleUpstream("mock", UpstreamConfig(type="openai", base_url="http://up.test/v1"),
                                  client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    app = create_app(policy, audit=audit, upstream_overrides={"mock": up})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://s") as c:
        await c.post("/v1/chat/completions", headers={"Authorization": "Bearer client-key"},
                     json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert seen["auth"] is None
