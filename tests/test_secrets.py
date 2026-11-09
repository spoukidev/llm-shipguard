import pytest

from eval.fakes import FAKES
from shipguard.filters.secrets import find_secrets, shannon_entropy


@pytest.mark.parametrize("name,kind", [
    ("FAKE_AWS_KEY", "AWS_ACCESS_KEY"),
    ("FAKE_SLACK_TOKEN", "SLACK_TOKEN"),
    ("FAKE_GITHUB_TOKEN", "GITHUB_TOKEN"),
    ("FAKE_OPENAI_KEY", "OPENAI_KEY"),
    ("FAKE_ANTHROPIC_KEY", "ANTHROPIC_KEY"),
    ("FAKE_STRIPE_KEY", "STRIPE_KEY"),
    ("FAKE_JWT", "JWT"),
    ("FAKE_PEM", "PEM_PRIVATE_KEY"),
])
def test_detects_each_secret_kind(name, kind):
    text = f"config value: {FAKES[name]} end"
    kinds = [f.kind for f in find_secrets(text)]
    assert kind in kinds


def test_aws_secret_needs_context():
    assert any(f.kind == "AWS_SECRET_KEY" for f in find_secrets(f"aws_secret_access_key = {FAKES['FAKE_AWS_SECRET']}"))
    assert not any(f.kind == "AWS_SECRET_KEY" for f in find_secrets("a" * 40))


def test_url_credentials_redacts_only_password():
    f = find_secrets(f"DATABASE_URL={FAKES['FAKE_DB_URL']}")
    assert [x.value for x in f if x.kind == "URL_CREDENTIALS"] == ["Sg-fake-Pass-42"]


def test_generic_password_requires_entropy_and_non_word():
    assert find_secrets(FAKES["FAKE_PASSWORD"])
    assert not find_secrets("password: required")
    assert not find_secrets("password = changeme")  # dictionary word, low signal


def test_pem_whole_block_is_one_finding():
    f = find_secrets(FAKES["FAKE_PEM"])
    assert len(f) == 1 and f[0].value.startswith("-----BEGIN") and f[0].value.rstrip().endswith("-----")


def test_benign_text_has_no_secrets():
    for t in ["The quick brown fox", "Use sk-learn for ML", "akia is a name", "token bucket algorithm", "ghp is fine"]:
        assert find_secrets(t) == [], t


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
