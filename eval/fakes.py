"""Runtime generation of *fake*, pattern-shaped secrets and payload encoders.

Nothing here is a real credential. Values are assembled at runtime so the
repository never contains strings that look like live tokens (which also
keeps GitHub push protection quiet).
"""

from __future__ import annotations

import base64
import codecs
import re

_FILL = "SHIPGUARDFAKE0123456789EXAMPLEXYZ" * 4

FAKES: dict[str, str] = {
    "FAKE_AWS_KEY": "AK" + "IA" + "SHIPGUARDFAKE001",
    "FAKE_AWS_SECRET": "fakeSecret/" + "ShipGuardExample0000000000000000"[:29],
    "FAKE_SLACK_TOKEN": "xo" + "xb-" + "000000000000-000000000000-" + "ShipGuardFakeTokenValue0",
    "FAKE_GITHUB_TOKEN": "gh" + "p_" + "ShipGuardFakeTokenValueForTests000000",
    "FAKE_OPENAI_KEY": "s" + "k-proj-" + "ShipGuardFakeKeyNotReal0000000000",
    "FAKE_ANTHROPIC_KEY": "s" + "k-ant-" + "ShipGuardFakeKeyNotReal0000000000",
    "FAKE_STRIPE_KEY": "s" + "k_test_" + "ShipGuardFakeKey00000000",
    "FAKE_JWT": "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJzaGlwZ3VhcmQtZmFrZSJ9.ShipGuardFakeSignature00",
    "FAKE_PEM": "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAshipguardFAKEkeyMaterialNotReal0000\n"
                "U2hpcEd1YXJkRmFrZUtleQ==\n-----END " + "RSA PRIVATE KEY-----",
    "FAKE_DB_URL": "postgres://app_user:" + "Sg-fake-Pass-42" + "@db.internal.test:5432/app",
    "FAKE_PASSWORD": "password=" + "Fake-Pass-9931!",
}


def _tags(s: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def _zw(s: str) -> str:
    return "\u200b".join(s)


_HOMO = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і", "x": "х", "y": "у"}


def _homoglyph(s: str) -> str:
    return "".join(_HOMO.get(c, c) if i % 2 == 0 else c for i, c in enumerate(s))


ENCODERS = {
    "b64": lambda s: base64.b64encode(s.encode()).decode(),
    "hex": lambda s: s.encode().hex(),
    "rot13": lambda s: codecs.encode(s, "rot13"),
    "tags": _tags,
    "zw": _zw,
    "homoglyph": _homoglyph,
    "reverse": lambda s: s[::-1],
    "spaced": lambda s: " ".join(s),
    "leet": lambda s: s.translate(str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"})),
}

_TPL = re.compile(r"\{\{(\w+)(?::([\s\S]*?))?\}\}")


def expand(text: str) -> str:
    """Expand ``{{FAKE_X}}`` and ``{{encoder:payload}}`` templates."""
    def sub(m: re.Match[str]) -> str:
        name, arg = m.group(1), m.group(2)
        if arg is None:
            return FAKES[name]
        return ENCODERS[name](expand(arg))
    prev = None
    while prev != text:
        prev, text = text, _TPL.sub(sub, text)
    return text
