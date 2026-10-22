"""The human-approval channel for `fill`: command resolution, the command contract, and that a
refusal stops the fill before the store is read."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from keychainlib import approval
from keychainlib.api import Keychain
from keychainlib.audit import Audit
from keychainlib.backends.fake import FakeBackend
from keychainlib.errors import MissingDependency, PolicyDenied, UsageError
from keychainlib.policy import Policy
from keychainlib.refs import parse_item_ref

from .conftest import SECRET
from .test_fill_units import REF, FakePage

ORIGIN = "https://site.tld"
RECORDER = (
    "import json, os, sys\n"
    "open(os.environ['REC'], 'w').write(json.dumps({'argv': sys.argv[1:], 'caller': os.environ.get(\n"
    "  'KEYCHAIN_CALLER'), 'env': {\n"
    "  k: v for k, v in os.environ.items() if k.startswith('KEYCHAIN_APPROVAL_')}}))\n"
    "sys.exit(int(os.environ.get('ANSWER', '0')))\n"
)


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    script = tmp_path / "approve.py"
    script.write_text(RECORDER)
    out = tmp_path / "rec.json"
    monkeypatch.setenv("REC", str(out))
    monkeypatch.setenv("ANSWER", "0")

    class Rec:
        command = (sys.executable, str(script))

        @staticmethod
        def seen() -> dict | None:
            return json.loads(out.read_text()) if out.exists() else None

    return Rec


def make(caller: str, policy: dict, backend: FakeBackend | None = None, **kw) -> Keychain:
    backend = backend or FakeBackend()
    backend.set(parse_item_ref(REF), SECRET.encode(), None, None, origin=ORIGIN)
    return Keychain(
        caller, backend=backend, policy=Policy.from_dict(policy), audit=Audit(enabled=False), **kw
    )


def grant(command, **extra) -> dict:
    entry = {"fill": [ORIGIN], "read": [REF]}
    return {"approval_cmd": list(command), "callers": {"ba": entry, **extra}}


# ── resolution ───────────────────────────────────────────────────────────────


def test_parse_command_string_and_list():
    assert approval.parse_command("tg-ctl ask --owner-only", "x") == ("tg-ctl", "ask", "--owner-only")
    assert approval.parse_command(["a b", "c"], "x") == ("a b", "c")
    for bad in ("", [], "'unclosed", 5, ["ok", 1]):
        with pytest.raises(UsageError):
            approval.parse_command(bad, "x")


def test_resolution_order_policy_then_env_then_default():
    env = {approval.ENV_COMMAND: "from-env --flag"}
    assert approval.resolve_command(("from-policy",), agent=False, environ=env) == (
        ("from-policy",),
        "policy",
    )
    assert approval.resolve_command(None, agent=False, environ=env) == (("from-env", "--flag"), "env")
    assert approval.resolve_command(None, agent=False, environ={}) == (approval.DEFAULT_COMMAND, "default")


def test_agent_session_cannot_pick_its_own_approver():
    env = {approval.ENV_COMMAND: "true"}
    assert approval.resolve_command(None, agent=True, environ=env) == (approval.DEFAULT_COMMAND, "default")


def test_policy_file_settings_are_validated():
    policy = Policy.from_dict(
        {"approval_cmd": "x y", "approval_timeout": 30, "callers": {"a": {"approve": False}}}
    )
    assert policy.approval_cmd == ("x", "y") and policy.approval_timeout == 30
    assert not policy.needs_approval("a") and policy.needs_approval("b") and not policy.needs_approval("user")
    assert Policy().approval_cmd is None and Policy().approval_timeout == approval.DEFAULT_TIMEOUT
    for bad in (
        {"approval_timeout": 0},
        {"approval_timeout": "5"},
        {"approval_timeout": True},
        {"approval_timeout": approval.MAX_TIMEOUT + 1},
        {"approval_cmd": ""},
        {"callers": {"a": {"approve": "no"}}},
    ):
        with pytest.raises(UsageError):
            Policy.from_dict(bad)


# ── the command contract ─────────────────────────────────────────────────────


def test_default_command_gets_its_timeout_as_a_flag(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(approval.subprocess, "run", fake_run)
    assert approval.request(approval.DEFAULT_COMMAND, "q?", timeout=42, caller="c", ref="r/a", origin=ORIGIN)
    argv, kw = calls[0]
    assert argv == ["tg-ctl", "ask", "--timeout", "42", "q?"]
    assert kw["stdin"] is subprocess.DEVNULL and kw["env"]["KEYCHAIN_APPROVAL_TIMEOUT"] == "42"


def test_exit_status_decides(recorder, monkeypatch):
    args = {"timeout": 5, "caller": "ba", "ref": REF, "origin": ORIGIN}
    assert approval.request(tuple(recorder.command), "q", **args) is True
    monkeypatch.setenv("ANSWER", "3")
    assert approval.request(tuple(recorder.command), "q", **args) is False


def test_missing_command_is_reported_not_approved():
    with pytest.raises(MissingDependency, match="not found"):
        approval.request(("/nonexistent/approver",), "q", timeout=1, caller="c", ref="r/a", origin=ORIGIN)


def test_a_command_that_outlives_the_timeout_is_a_refusal(monkeypatch):
    monkeypatch.setattr(approval, "_GRACE", 0)
    sleeper = (sys.executable, "-c", "import time; time.sleep(30)")
    assert approval.request(sleeper, "q", timeout=1, caller="c", ref="r/a", origin=ORIGIN) is False


# ── fill ─────────────────────────────────────────────────────────────────────


def test_fill_asks_the_human_and_proceeds_on_approval(recorder, monkeypatch):
    page = FakePage()
    kc = make("ba", grant(recorder.command))
    monkeypatch.setenv("KEYCHAIN_CALLER", "ba")
    assert kc.fill(REF, page, "#pw")["filled"] is True and page.value == SECRET
    seen = recorder.seen()
    assert seen["caller"] is None  # an approver does not inherit our identity
    (prompt,) = seen["argv"]
    assert "`ba`" in prompt and REF in prompt and ORIGIN in prompt and "password" in prompt
    assert seen["env"] == {
        "KEYCHAIN_APPROVAL_TIMEOUT": str(approval.DEFAULT_TIMEOUT),
        "KEYCHAIN_APPROVAL_CALLER": "ba",
        "KEYCHAIN_APPROVAL_REF": REF,
        "KEYCHAIN_APPROVAL_ORIGIN": ORIGIN,
    }
    assert SECRET not in json.dumps(seen)


def test_a_refusal_stops_the_fill_before_the_store_is_read(recorder, monkeypatch):
    monkeypatch.setenv("ANSWER", "1")
    backend = FakeBackend()
    reads = []
    original = backend.get
    backend.get = lambda ref: reads.append(ref) or original(ref)
    page = FakePage()
    with pytest.raises(PolicyDenied, match="did not approve"):
        make("ba", grant(recorder.command), backend).fill(REF, page, "#pw")
    assert reads == [] and page.value is None


def test_nobody_is_asked_about_a_fill_that_would_be_refused_anyway(recorder):
    page = FakePage("https://evil.tld/login")
    with pytest.raises(PolicyDenied):
        make("ba", grant(recorder.command, ba={"fill": ["https://evil.tld"], "read": [REF]})).fill(
            REF, page, "#pw"
        )
    assert recorder.seen() is None


def test_the_human_user_and_released_callers_are_not_asked(recorder):
    page = FakePage()
    assert make("user", grant(recorder.command)).fill(REF, page, "#pw")["filled"] is True
    assert recorder.seen() is None
    released = grant(recorder.command, ba={"fill": [ORIGIN], "read": [REF], "approve": False})
    assert make("ba", released).fill(REF, FakePage(), "#pw")["filled"] is True
    assert recorder.seen() is None


def test_env_command_is_used_outside_agent_sessions_only(recorder, monkeypatch):
    monkeypatch.setenv(approval.ENV_COMMAND, " ".join(recorder.command))
    monkeypatch.delenv("KEYCHAIN_AGENT", raising=False)
    for marker in (
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "OMPCODE",
        "OPENCODE",
        "GEMINI_CLI",
        "CURSOR_AGENT",
        "PI_CODING_AGENT",
    ):
        monkeypatch.delenv(marker, raising=False)
    policy = {"callers": {"ba": {"fill": [ORIGIN], "read": [REF]}}}
    assert make("ba", policy).fill(REF, FakePage(), "#pw")["filled"] is True
    assert recorder.seen() is not None


def test_the_audit_journal_records_the_approval_without_values(recorder, tmp_path):
    audit = Audit(path=tmp_path / "audit.jsonl")
    kc = make("ba", grant(recorder.command))
    kc.audit = audit
    kc.fill(REF, FakePage(), "#pw")
    text = (tmp_path / "audit.jsonl").read_text()
    assert '"approval": "approved"' in text and SECRET not in text


def test_a_tg_ctl_ask_command_with_options_still_gets_the_time_limit(monkeypatch):
    calls = []
    monkeypatch.setattr(
        approval.subprocess,
        "run",
        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0),
    )
    command = ("tg-ctl", "ask", "--owner-only")
    assert approval.request(command, "q?", timeout=7, caller="c", ref="r/a", origin=ORIGIN)
    assert calls == [["tg-ctl", "ask", "--timeout", "7", "--owner-only", "q?"]]
    calls.clear()
    explicit = ("tg-ctl", "ask", "--timeout", "900")  # not doubled; approval_timeout still bounds the wait
    assert approval.request(explicit, "q?", timeout=7, caller="c", ref="r/a", origin=ORIGIN)
    assert calls == [["tg-ctl", "ask", "--timeout", "900", "q?"]]
    calls.clear()
    equals_form = ("tg-ctl", "ask", "--timeout=900")
    assert approval.request(equals_form, "q?", timeout=7, caller="c", ref="r/a", origin=ORIGIN)
    assert calls == [["tg-ctl", "ask", "--timeout=900", "q?"]]


def test_a_value_with_a_line_break_is_refused_not_silently_changed():
    backend = FakeBackend()
    backend.set(parse_item_ref(REF), b"two\nlines", None, None, origin=ORIGIN)
    kc = Keychain(
        "ba",
        backend=backend,
        policy=Policy.from_dict({"callers": {"ba": {"fill": [ORIGIN], "approve": False}}}),
        audit=Audit(enabled=False),
    )
    page = FakePage()
    with pytest.raises(UsageError, match="line break"):
        kc.fill(REF, page, "#pw")
    assert page.value is None


def test_an_empty_origin_flag_is_an_error_not_no_narrowing(recorder):
    with pytest.raises(UsageError, match="origin"):
        make("ba", grant(recorder.command)).fill(REF, FakePage(), "#pw", origin="")
    assert recorder.seen() is None  # refused before the human is asked
