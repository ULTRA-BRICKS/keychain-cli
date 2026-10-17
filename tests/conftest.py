from __future__ import annotations

import io
import sys

import pytest

from keychainlib import cli
from keychainlib.api import Keychain
from keychainlib.audit import Audit
from keychainlib.backends.fake import FakeBackend
from keychainlib.context import AGENT_MARKERS, AGENT_PREFIXES
from keychainlib.policy import Policy

SECRET = "s3cr3t-Valu3-🔑"


def scrubbed_env(environ) -> dict[str, str]:
    """A copy of ``environ`` with every keychain variable and agent-harness marker removed."""
    return {
        k: v
        for k, v in environ.items()
        if not k.startswith(("KEYCHAIN_", *AGENT_PREFIXES)) and k not in AGENT_MARKERS
    }


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """No test may touch the user's policy, journal, skills or real agent markers."""
    import os

    for name in set(os.environ) - set(scrubbed_env(os.environ)):
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


class FakeStdin:
    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)

    def isatty(self) -> bool:
        return False


class Harness:
    def __init__(self, tmp_path, monkeypatch) -> None:
        self.backend = FakeBackend()
        self.policy = Policy()
        self.audit = Audit(tmp_path / "audit.jsonl")
        self.monkeypatch = monkeypatch

    def keychain(self, caller=None) -> Keychain:
        return Keychain(caller, backend=self.backend, policy=self.policy, audit=self.audit)

    def run(self, argv: list[str], stdin: bytes = b"") -> int:
        self.monkeypatch.setattr(sys, "stdin", FakeStdin(stdin))
        return cli.main(argv, keychain_factory=lambda a: self.keychain(a.caller))


@pytest.fixture
def h(tmp_path, monkeypatch) -> Harness:
    return Harness(tmp_path, monkeypatch)
