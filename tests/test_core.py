"""Refs, the Secret type, caller resolution and policy rules."""

from __future__ import annotations

import logging
import pickle

import pytest

from keychainlib.context import resolve_caller
from keychainlib.errors import PolicyDenied, UsageError
from keychainlib.policy import READ, WRITE, Policy
from keychainlib.refs import Ref, SystemRef, parse_ref
from keychainlib.secret import Secret

from .conftest import SECRET


@pytest.mark.parametrize("text", ["tg-cli/bot-token", "3d-cli/thingiverse", "a/b@c.d", "svc.x/user+tag:1"])
def test_valid_refs(text):
    assert str(parse_ref(text)) == text


@pytest.mark.parametrize(
    "text",
    [
        "",
        "nosep",
        "/acct",
        "svc/",
        "-svc/a",
        "svc/-a",
        "svc/a b",
        'svc/a"b',
        "svc/a\\b",
        "svc/a/b",
        "s" * 65 + "/a",
        "svc/a\n",
    ],
)
def test_invalid_refs(text):
    with pytest.raises(UsageError):
        parse_ref(text)


def test_system_ref():
    assert parse_ref("system:login/12") == SystemRef("login/12")
    with pytest.raises(UsageError):
        parse_ref("system:a b")


def test_secret_never_prints(caplog):
    s = Secret(SECRET)
    percent = "%s" % (s,)  # noqa: UP031 - %-formatting is one of the paths under test
    for rendered in (str(s), repr(s), f"{s}", f"{s!r}", percent, str([s]), str({"k": s})):
        assert SECRET not in rendered
    logging.getLogger("t").warning("token %s", s)
    assert SECRET not in caplog.text
    assert s.reveal() == SECRET
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert s == Secret(SECRET) and s != Secret("other")


def test_caller_resolution():
    assert resolve_caller(None, {}) == "user"
    assert resolve_caller(None, {"CLAUDECODE": "1"}) == "agent"
    assert resolve_caller(None, {"KEYCHAIN_CALLER": "tg-cli", "OMPCODE": "1"}) == "tg-cli"
    assert resolve_caller("x", {"KEYCHAIN_CALLER": "y"}) == "x"
    # an agent session cannot switch itself back to "human"
    assert resolve_caller(None, {"CLAUDECODE": "1", "KEYCHAIN_AGENT": "0"}) == "agent"
    assert resolve_caller(None, {"CODEX_ANYTHING": "x"}) == "agent"
    assert resolve_caller(None, {"KEYCHAIN_AGENT": "1"}) == "agent"
    with pytest.raises(UsageError):
        resolve_caller("user", {"CLAUDECODE": "1"})
    with pytest.raises(UsageError):
        resolve_caller("bad name", {})


def test_policy_rules():
    p = Policy.from_dict(
        {
            "callers": {
                "market": {
                    "read": ["3d-cli/*", "system:login/*"],
                    "write": ["market-shared/*"],
                    "reveal": False,
                }
            }
        }
    )
    own, other = Ref("market", "x"), Ref("3d-cli", "printops")
    assert p.allows("user", WRITE, other)
    assert p.allows("market", WRITE, own)
    assert p.allows("market", READ, other) and not p.allows("market", WRITE, other)
    assert p.allows("market", READ, SystemRef("login/3"))
    assert not p.allows("market", READ, SystemRef("iCloud/3"))
    assert not p.allows("tg-cli", READ, other)
    assert not p.allows("tg-cli", READ, SystemRef("login/3"))  # system items are never owned
    star = Policy.from_dict({"callers": {"wide": {"read": ["*"]}}})
    assert star.allows("wide", READ, other)
    assert not star.allows("wide", READ, SystemRef("login/3"))  # `*` is not a system grant
    with pytest.raises(PolicyDenied) as exc:
        p.check("tg-cli", READ, other)
    assert "callers.tg-cli" in exc.value.fix


def test_reveal_rules():
    p = Policy.from_dict({"callers": {"quiet": {"reveal": False}, "loud": {"reveal": True, "read": ["x/*"]}}})
    assert p.may_reveal("agent", agent=False)
    assert p.may_reveal("tg-cli", agent=False)
    assert not p.may_reveal("agent", agent=True)
    assert not p.may_reveal("user", agent=True)
    assert not p.may_reveal("tg-cli", agent=True)  # owning a namespace is not enough
    assert not p.may_reveal("quiet", agent=True)
    assert p.may_reveal("loud", agent=True)


@pytest.mark.parametrize(
    "data",
    [
        {"other": 1},
        {"callers": {"a": {"read": "x/*"}}},
        {"callers": {"a": {"reveal": "yes"}}},
        {"callers": {"a": {"admin": True}}},
    ],
)
def test_policy_rejects_malformed(data):
    with pytest.raises(UsageError):
        Policy.from_dict(data)


def test_policy_file(tmp_path, monkeypatch):
    path = tmp_path / "policy.toml"
    path.write_text('[callers.m]\nread = ["a/*"]\n')
    assert Policy.load(path).allows("m", READ, Ref("a", "b"))
    path.write_text("[callers.m\n")
    with pytest.raises(UsageError):
        Policy.load(path)
    assert Policy.load(tmp_path / "absent.toml").callers == {}


@pytest.mark.parametrize("callers", [["x"], "bad", 3])
def test_policy_callers_must_be_table(callers):
    with pytest.raises(UsageError):
        Policy.from_dict({"callers": callers})
