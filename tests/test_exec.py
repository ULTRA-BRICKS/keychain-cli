"""`keychain exec`: injection reaches the child, output is redacted, exit codes propagate."""

from __future__ import annotations

import sys

import pytest

from keychainlib.execution import Redactor
from keychainlib.refs import Ref

from .conftest import SECRET

PY = sys.executable


@pytest.fixture
def stored(h):
    h.backend.set(Ref("tool", "token"), SECRET.encode(), None, None)
    return h


def test_env_injection_and_redaction(stored, capfd):
    code = (
        f"import os,sys; v=os.environ['TOK']; assert v=={SECRET!r}; "
        "print('value:', v); print('err', v, file=sys.stderr)"
    )
    assert stored.run(["exec", "--env", "TOK=tool/token", "--", PY, "-c", code]) == 0
    out, err = capfd.readouterr()
    assert SECRET not in out + err
    assert "value: ***" in out and "err ***" in err


def test_no_redact_passthrough_in_subprocess_mode(stored, capfd):
    # --stdin keeps a parent process even with --no-redact, so the test can observe output
    code = "import sys; print(sys.stdin.read())"
    assert stored.run(["exec", "--stdin", "tool/token", "--no-redact", "--", PY, "-c", code]) == 0
    assert SECRET in capfd.readouterr().out


def test_stdin_injection_redacted(stored, capfd):
    code = f"import sys; d=sys.stdin.read(); assert d=={SECRET!r}; print(d)"
    assert stored.run(["exec", "--stdin", "tool/token", "--", PY, "-c", code]) == 0
    assert capfd.readouterr().out.strip() == "***"


def test_exit_code_and_missing_command(stored, capfd):
    assert stored.run(["exec", "--env", "T=tool/token", "--", PY, "-c", "raise SystemExit(7)"]) == 7
    assert stored.run(["exec", "--env", "T=tool/token", "--", "/nonexistent/cmd"]) == 127
    assert stored.run(["exec", "--", PY, "-c", "0"]) == 2  # nothing to inject
    assert stored.run(["exec", "--env", "T=tool/missing", "--", PY, "-c", "0"]) == 4


def test_exec_policy_applies(stored, capfd):
    assert (
        stored.run(["exec", "--caller", "other", "--env", "T=tool/token", "--", PY, "-c", "print('ran')"])
        == 8
    )
    assert "ran" not in capfd.readouterr().out


def test_caller_not_inherited(stored, capfd, monkeypatch):
    monkeypatch.setenv("KEYCHAIN_CALLER", "tool")
    code = "import os; print(os.environ.get('KEYCHAIN_CALLER'))"
    assert stored.run(["exec", "--env", "T=tool/token", "--", PY, "-c", code]) == 0
    assert capfd.readouterr().out.strip() == "None"


def test_short_secret_refused_for_redaction(h, capfd):
    h.backend.set(Ref("tool", "pin"), b"12", None, None)
    assert h.run(["exec", "--env", "P=tool/pin", "--", PY, "-c", "0"]) == 2


@pytest.mark.parametrize("split", range(1, 12))
def test_redactor_catches_value_split_across_chunks(split):
    secret = b"abcdefghijk"
    data = b"xx" + secret + b"yy" + secret
    r = Redactor([secret])
    out = r.feed(data[:split]) + r.feed(data[split : split + 5]) + r.feed(data[split + 5 :]) + r.flush()
    assert out == b"xx***yy***"


def test_redactor_longest_first():
    r = Redactor([b"abcd", b"abcdef"])
    assert r.feed(b"-abcdef-abcd-") + r.flush() == b"-***-***-"


def test_encoded_forms_are_redacted(stored, capfd):
    code = (
        "import base64, json, os, urllib.parse; v = os.environb[b'T']; "
        "print('Basic', base64.b64encode(b'me:' + v).decode()); "
        "print('q', urllib.parse.quote(v, safe='')); print('j', json.dumps(v.decode())); "
        "print('r', repr(v)); print('h', v.hex())"
    )
    assert stored.run(["exec", "--env", "T=tool/token", "--", PY, "-c", code]) == 0
    out = capfd.readouterr().out
    import base64
    import json
    import urllib.parse

    raw = SECRET.encode()
    for leaked in (base64.b64encode(b"me:" + raw)[4:-4], urllib.parse.quote(raw, safe="").encode(),
                   json.dumps(SECRET)[1:-1].encode(), repr(raw)[2:-1].encode(), raw.hex().encode()):
        assert leaked.decode() not in out


def test_redactor_short_needle_does_not_preempt_longer():
    r = Redactor([b"hunter22", b"postgres://u:hunter22@db/x"])
    out = r.feed(b"url=postgres://u:hunter22") + r.feed(b"@db/x end") + r.flush()
    assert out == b"url=*** end"


def test_reader_gone_does_not_hang(stored):
    import subprocess

    code = "import sys\nwhile True: sys.stdout.write('x' * 1000 + '\\n')"
    p = subprocess.run(f"{PY} -m keychainlib --version >/dev/null", shell=True, check=False)
    assert p.returncode == 0
    from keychainlib.execution import _pump

    r, w = __import__("os").pipe()
    import os
    os.write(w, b"data")
    os.close(w)

    class Gone:
        def write(self, _):
            raise BrokenPipeError

        def flush(self):
            pass

    _pump(os.fdopen(r, "rb"), Gone(), Redactor([b"zzzz"]))  # returns instead of raising
    assert code


def test_non_utf8_secret_injected_exactly(h, capfd):
    h.backend.set(Ref("tool", "bin"), b"\xff\xfe\xfd\xfc", None, None)
    code = "import os, sys; sys.exit(0 if os.environb[b'B'] == b'\\xff\\xfe\\xfd\\xfc' else 3)"
    assert h.run(["exec", "--env", "B=tool/bin", "--", PY, "-c", code]) == 0
