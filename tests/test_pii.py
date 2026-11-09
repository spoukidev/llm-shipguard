import pytest

from shipguard.filters.pii import find_pii, iban_ok, luhn_ok


@pytest.mark.parametrize("text,kind", [
    ("mail me at jane.doe@mail.example", "EMAIL"),
    ("call (555) 010-4477 today", "PHONE"),
    ("call +44 20 7946 0958", "PHONE"),
    ("card 4111 1111 1111 1111", "CREDIT_CARD"),
    ("card 5555-5555-5555-4444", "CREDIT_CARD"),
    ("ssn 123-45-6789", "US_SSN"),
    ("iban GB82 WEST 1234 5698 7654 32", "IBAN"),
])
def test_detects(text, kind):
    assert kind in [f.kind for f in find_pii(text)]


@pytest.mark.parametrize("text", [
    "version 3.11.4 released", "order 2024-05-17", "the year 1999", "id 123456789012",
    "4111 1111 1111 1112",  # Luhn fails
    "ssn 000-12-3456", "port 8080", "timestamp 1699999999",
])
def test_no_false_positive(text):
    assert find_pii(text) == []


def test_ip_only_when_enabled():
    assert find_pii("host 10.0.0.1") == []
    assert [f.kind for f in find_pii("host 10.0.0.1", entities=["IP_ADDRESS"])] == ["IP_ADDRESS"]


def test_checksums():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert iban_ok("GB82WEST12345698765432") and not iban_ok("GB00WEST12345698765432")
