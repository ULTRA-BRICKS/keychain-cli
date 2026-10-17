"""The CLI over the fake backend: value hygiene, policy, exit codes, audit."""

from __future__ import annotations

import json
import sys

from keychainlib.policy import Grant
from keychainlib.refs import Ref

from .conftest import SECRET

REF = "tg-cli/bot-token"


def _all_output(capsys) -> str:
    out = capsys.readouterr()
    return out.out + out.err


def test_set_get_roundtrip_strips_one_newline(h, capsys):
    assert h.run(["set", REF, "--label", "Bot", "--note", "prod"], stdin=SECRET.encode() + b"\n") == 0
    assert h.backend.items[Ref("tg-cli", "bot-token")][0] == SECRET.encode()
    capsys.readouterr()
    assert h.run(["get", REF, "--reveal"]) == 0
    assert capsys.readouterr().out == SECRET  # no newline when stdout is not a TTY


def test_set_raw_keeps_bytes(h):
    h.run(["set", REF, "--raw"], stdin=b"abc\n")
    assert h.backend.get(Ref("tg-cli", "bot-token")) == b"abc\n"


def test_set_refuses_empty(h):
    assert h.run(["set", REF], stdin=b"\n") == 2
    assert h.backend.items == {}


def test_argv_value_option_does_not_exist():
    from keychainlib.cli import build_parser

    for action in build_parser()._subparsers._group_actions[0].choices["set"]._actions:
        assert not {"--value", "--password", "--secret", "-w"} & set(action.option_strings)


def test_get_requires_reveal(h, capsys):
    h.backend.set(Ref("tg-cli", "bot-token"), SECRET.encode(), None, None)
    assert h.run(["get", REF]) == 2
    assert SECRET not in _all_output(capsys)


def test_agent_session_reveal_needs_human_grant(h, capsys, monkeypatch):
    h.backend.set(Ref("tg-cli", "bot-token"), SECRET.encode(), None, None)
    h.backend.set(Ref("agent", "own"), SECRET.encode(), None, None)
    monkeypatch.setenv("KEYCHAIN_AGENT", "1")
    assert h.run(["get", REF, "--reveal"]) == 8  # default caller `agent`, foreign namespace
    assert h.run(["get", "agent/own", "--reveal"]) == 8  # `agent` never prints
    assert h.run(["get", REF, "--reveal", "--caller", "tg-cli"]) == 8  # claiming a name is not enough
    err = _all_output(capsys)
    assert SECRET not in err and "--caller" not in err  # the refusal does not teach a bypass
    # exec --no-redact is printing by another name
    code = "import os; print(os.environ['T'])"
    assert (
        h.run(
            [
                "exec",
                "--caller",
                "tg-cli",
                "--no-redact",
                "--env",
                f"T={REF}",
                "--",
                sys.executable,
                "-c",
                code,
            ]
        )
        == 8
    )
    # redacted exec is the agent path
    assert h.run(["exec", "--caller", "tg-cli", "--env", f"T={REF}", "--", sys.executable, "-c", code]) == 0
    assert capsys.readouterr().out == "***\n"
    h.policy.callers["tg-cli"] = Grant(reveal=True)  # the human's grant
    assert h.run(["get", REF, "--reveal", "--caller", "tg-cli"]) == 0
    assert capsys.readouterr().out == SECRET


def test_exec_authorizes_every_ref_before_fetching(h, capsys):
    h.backend.set(Ref("tool", "a"), b"aaaa", None, None)
    h.backend.locked = True  # a fetch would raise Locked (9); a policy refusal must come first
    assert (
        h.run(
            [
                "exec",
                "--caller",
                "tool",
                "--env",
                "A=tool/a",
                "--env",
                "B=other/b",
                "--",
                sys.executable,
                "-c",
                "0",
            ]
        )
        == 8
    )


def test_bad_arguments_are_not_echoed(h, capsys):
    pasted = "ghp_" + "Z" * 30 + " oops"
    assert h.run(["get", pasted, "--reveal"]) == 2
    assert h.run(["exec", "--env", pasted, "--", sys.executable, "-c", "0"]) == 2
    assert pasted not in _all_output(capsys)


def test_cross_namespace_denied_before_backend(h, capsys):
    h.backend.set(Ref("tg-cli", "bot-token"), SECRET.encode(), None, None)
    h.backend.locked = True  # a denied call must not even reach (and unlock) the store
    assert h.run(["get", REF, "--reveal", "--caller", "3d-cli"]) == 8
    assert h.run(["set", REF, "--caller", "3d-cli"], stdin=b"zzzz") == 8
    assert "may not" in capsys.readouterr().err


def test_exit_codes(h, capsys):
    assert h.run(["exists", REF]) == 4
    assert h.run(["get", REF, "--reveal"]) == 4
    assert h.run(["delete", REF]) == 4
    assert h.run(["get", "bad ref", "--reveal"]) == 2
    h.backend.set(Ref("tg-cli", "bot-token"), b"vvvv", None, None)
    assert h.run(["exists", REF]) == 0
    h.backend.locked = True
    assert h.run(["get", REF, "--reveal"]) == 9
    h.backend.locked = False
    assert h.run(["delete", REF]) == 0
    assert h.run(["exists", REF]) == 4


def test_list_and_info_never_include_values(h, capsys):
    h.backend.set(Ref("tg-cli", "bot-token"), SECRET.encode(), "Bot", "note")
    h.backend.set(Ref("3d-cli", "printops"), SECRET.encode(), None, None)
    assert h.run(["list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [d["ref"] for d in data] == ["3d-cli/printops", "tg-cli/bot-token"]
    assert h.run(["list", "--caller", "tg-cli"]) == 0
    out = capsys.readouterr().out
    assert "tg-cli/bot-token" in out and "3d-cli" not in out  # only what the caller may read
    assert h.run(["info", REF, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["label"] == "Bot"
    for argv in (["list"], ["info", REF], ["audit", "--json"], ["policy"]):
        h.run(argv)
        assert SECRET not in _all_output(capsys)


def test_audit_records_without_values(h, capsys, monkeypatch):
    h.run(["set", REF], stdin=SECRET.encode())
    h.run(["get", REF, "--reveal"])
    h.run(["get", REF, "--reveal", "--caller", "other"])
    h.run(["get", REF])
    h.run(["set", REF, "--caller", "other"], stdin=b"zzzz")
    monkeypatch.setenv("KEYCHAIN_AGENT", "1")
    h.run(["get", REF, "--reveal", "--caller", "tg-cli"])
    capsys.readouterr()
    text = h.audit.path.read_text()
    assert SECRET not in text
    entries = [json.loads(line) for line in text.splitlines()]
    assert [(e["op"], e["outcome"], e["agent"]) for e in entries] == [
        ("set", "ok", False),
        ("reveal", "ok", False),
        ("reveal", "PolicyDenied", False),
        ("reveal", "NoRevealFlag", False),
        ("set", "PolicyDenied", False),
        ("reveal", "PolicyDenied", True),
    ]
    assert oct(h.audit.path.stat().st_mode & 0o777) == "0o600"


def test_system_list_filters_only_on_safe_attributes(h, capsys):
    h.backend.add_system("login/1", b"vvvv", "x", {"url": "https://u:pw@x.example/p?token=t1"})
    assert h.run(["system", "list", "--attr", "otpauth=otpauth://x"]) == 2
    assert h.run(["system", "list", "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)[0]["attributes"]["url"]
    assert shown == "https://x.example/p"  # userinfo and query stripped


def test_system_items(h, capsys):
    h.backend.add_system(
        "login/7",
        SECRET.encode(),
        "github.com",
        {
            "xdg:schema": "web",
            "url": "https://github.com",
            "username": "alex",
            "otpauth": "otpauth://totp/x?secret=TOTPSEED",
        },
    )
    assert h.run(["system", "list", "--match", "github"]) == 0
    out = capsys.readouterr().out
    assert "system:login/7" in out and "TOTPSEED" not in out  # unsafe attributes are hidden
    assert h.run(["system", "get", "login/7", "--reveal"]) == 0
    assert capsys.readouterr().out == SECRET
    assert h.run(["system", "get", "login/7", "--reveal", "--caller", "tool"]) == 8


def test_policy_check_command(h, capsys):
    assert h.run(["policy", "x/y", "--caller", "x"]) == 0
    assert h.run(["policy", "x/y", "--caller", "z"]) == 8


def test_system_caller_at_parent_level_is_honoured(h):
    h.backend.add_system("login/9", b"vvvv", "x", {})
    assert h.run(["system", "get", "login/9", "--reveal", "--caller", "tool"]) == 8
