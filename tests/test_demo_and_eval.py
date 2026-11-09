"""End-to-end: the before/after demo over real HTTP, and the eval targets."""

import socket
from pathlib import Path

import pytest

from eval import run_eval


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_demo_scenarios_pass(monkeypatch, tmp_path):
    from demo import run_demo

    monkeypatch.setenv("SHIPGUARD_AUDIT_DB", f"sqlite:///{tmp_path}/a.db")
    mp, gp = _port(), _port()
    monkeypatch.setenv("MOCK_UPSTREAM_URL", f"http://127.0.0.1:{mp}/v1")
    monkeypatch.setenv("SHIPGUARD_UPSTREAM", "mock-http")
    assert run_demo.main(["--start", "--mock-port", str(mp), "--gateway-port", str(gp)]) == 0


def test_eval_meets_targets(tmp_path):
    rc = run_eval.main(["--out", str(tmp_path), "--quiet"])
    assert rc == 0
    assert (tmp_path / "report_dev.md").exists()


def test_corpus_attacks_are_valid():
    """Every dev attack must succeed against the unguarded mock, or it measures nothing."""
    import asyncio

    from shipguard.config import load_policy

    attacks = run_eval.load_jsonl(Path(run_eval.ROOT / "corpus" / "attacks.jsonl"))
    res = asyncio.run(run_eval.run_corpus(run_eval.policy_for_eval(load_policy()), attacks, []))
    assert res["attacks_invalid_ids"] == []


@pytest.mark.parametrize("name", ["attacks.jsonl", "benign.jsonl", "holdout_attacks.jsonl", "holdout_benign.jsonl"])
def test_corpus_is_educational(name):
    text = (run_eval.ROOT / "corpus" / name).read_text(encoding="utf-8")
    import re

    for host in re.findall(r"https?://([\w.-]+)", text):
        assert host.endswith((".test", ".example", ".invalid")) or host in {"localhost", "169.254.169.254"}, host
    for email_dom in re.findall(r"@([\w-]+(?:\.[\w-]+)+)", text):
        assert email_dom.endswith((".test", ".example", ".invalid")), email_dom
