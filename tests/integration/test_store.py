"""Scenarios 1–5 of the integration suite: real binary, real gnome-keyring, real consumers."""

from __future__ import annotations

import http.server
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time

import pytest

from keychainlib.backends.secretservice import SERVICE, SERVICE_PATH, SecretServiceBackend
from keychainlib.refs import Ref

from .conftest import BIN, BUS, INTEGRATION, ROOT

pytestmark = INTEGRATION


def _value() -> str:
    return "it-" + secrets.token_urlsafe(18)


class AuthServer:
    """Answers 200 only for `Authorization: Bearer <expected>`; never logs a request."""

    def __init__(self, expected: str) -> None:
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                ok = self.headers.get("Authorization") == f"Bearer {expected}"
                outer.hits.append(ok)
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.hits: list[bool] = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.mark.skipif(not shutil.which("curl"), reason="curl is not installed")
def test_exec_feeds_a_real_consumer(kc):
    value = _value()
    assert kc("set", "kc-it/api", stdin=value.encode()).returncode == 0
    server = AuthServer(value)
    try:
        script = 'curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$0"'
        r = kc("exec", "--env", "TOKEN=kc-it/api", "--", "sh", "-c", script, server.url)
        assert (r.returncode, r.stdout) == (0, b"200"), r.stderr
        # the consumer prints the header itself: the value is masked in what we see
        r = kc("exec", "--env", "TOKEN=kc-it/api", "--", "sh", "-c",
               'curl -sv -o /dev/null -H "Authorization: Bearer $TOKEN" "$0"', server.url)
        assert r.returncode == 0 and b"Bearer ***" in r.stderr
        assert value.encode() not in r.stdout + r.stderr
        # without the secret the server refuses
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", server.url],
                           capture_output=True, check=False)
        assert r.stdout == b"401"
        assert server.hits == [True, True, False]
    finally:
        server.server.shutdown()
        kc("delete", "kc-it/api")


LIBRARY_PROBE = """
import sys
sys.path.insert(0, {root!r})
from keychainlib import Keychain
from keychainlib.errors import PolicyDenied
kc = Keychain("kc-tool-a", store={label!r})
own = kc.get("kc-tool-a/key").reveal() == sys.argv[1]
try:
    other = kc.get("kc-tool-b/key").reveal() == sys.argv[2]
except PolicyDenied:
    other = "denied"
print(repr(kc.get("kc-tool-a/key")), own, other)
"""


def test_library_from_another_utility(kc, collection):
    a, b = _value(), _value()
    assert kc("set", "kc-tool-a/key", stdin=a.encode()).returncode == 0
    assert kc("set", "kc-tool-b/key", stdin=b.encode()).returncode == 0
    code = LIBRARY_PROBE.format(root=str(ROOT), label=collection["label"])
    try:
        # `python3 -I` like bin/keychain; the values travel as argv only inside this test
        r = subprocess.run([sys.executable, "-I", "-c", code, a, b], capture_output=True,
                           env=kc.env(), timeout=60, check=False)
        assert r.stdout.split() == [b"Secret(***)", b"True", b"denied"], r.stderr
        kc.policy('[callers.kc-tool-a]\nread = ["kc-tool-b/*"]\n')
        r = subprocess.run([sys.executable, "-I", "-c", code, a, b], capture_output=True,
                           env=kc.env(), timeout=60, check=False)
        assert r.stdout.split() == [b"Secret(***)", b"True", b"True"], r.stderr
    finally:
        kc("delete", "kc-tool-a/key")
        kc("delete", "kc-tool-b/key")


def test_agent_session_never_prints(kc):
    value = _value()
    assert kc("set", "kc-it/agent", stdin=value.encode()).returncode == 0
    try:
        # the utility owns kc-it/*, and still may not print inside an agent session
        assert kc("get", "kc-it/agent", "--reveal", agent=True, caller="kc-it").returncode == 8
        assert kc("get", "kc-it/agent", "--reveal", agent=True).returncode == 8
        r = kc("exec", "--no-redact", "--env", "T=kc-it/agent", "--", "true", agent=True, caller="kc-it")
        assert r.returncode == 8
        r = kc("exec", "--env", "T=kc-it/agent", "--", "printenv", "T", agent=True, caller="kc-it")
        assert (r.returncode, r.stdout.strip()) == (0, b"***")
        assert value.encode() not in kc.audit_text().encode()
    finally:
        kc("delete", "kc-it/agent")


@pytest.mark.skipif(not shutil.which("script"), reason="util-linux `script` is not installed")
def test_headless_locked_then_tty_unlock(kc, collection):
    value = _value()
    b = SecretServiceBackend(collection=collection["label"], interactive=False, address=BUS or None)
    b.set(Ref("kc-it", "lock"), value.encode(), None, None)
    b._call(SERVICE_PATH, SERVICE, "Lock", "ao", [[collection["path"]]])
    # No DISPLAY, no TTY, no XDG_RUNTIME_DIR: like cron or `ssh host cmd`. The bus comes from
    # /run/user/<uid>/bus when that is the session bus; under dbus-run-session (CI) it has to
    # be passed explicitly.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(kc.config.parent),
           "XDG_CONFIG_HOME": str(kc.config), "XDG_STATE_HOME": str(kc.state),
           "KEYCHAIN_STORE": collection["label"]}
    if os.environ.get("LD_LIBRARY_PATH"):  # a toolcache Python (CI) cannot start without it
        env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
    if BUS and BUS != f"unix:path=/run/user/{os.getuid()}/bus":
        env["DBUS_SESSION_BUS_ADDRESS"] = BUS
    start = time.monotonic()
    r = subprocess.run(["env", "-i", *(f"{k}={v}" for k, v in env.items()), str(BIN), "get", "kc-it/lock",
                        "--reveal"], capture_output=True, timeout=30, check=False)
    assert r.returncode == 9, r.stderr
    assert time.monotonic() - start < 10
    # `keychain unlock` on a pseudo-terminal; getpass flushes typeahead, so type after a pause
    feeder = subprocess.Popen(
        ["env", "-i", *(f"{k}={v}" for k, v in env.items()), "script", "-qec", f"{BIN} unlock", "/dev/null"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    feeder.stdin.write(collection["password"].encode() + b"\n")
    feeder.stdin.flush()
    assert feeder.wait(30) == 0
    r = subprocess.run(["env", "-i", *(f"{k}={v}" for k, v in env.items()), str(BIN), "get", "kc-it/lock",
                        "--reveal"], capture_output=True, timeout=30, check=False)
    assert (r.returncode, r.stdout == value.encode()) == (0, True), r.stderr
    b.delete(Ref("kc-it", "lock"))
    b.close()


@pytest.mark.parametrize("round_", range(3))
def test_parallel_set_of_one_ref_leaves_one_item(kc, collection, round_):
    ref = f"kc-it/race-{round_}"
    procs = [
        subprocess.Popen([str(BIN), "set", ref], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE, env=kc.env())
        for _ in range(12)
    ]
    errors = [p.communicate(f"race-{i}-{secrets.token_hex(4)}".encode(), timeout=90)[1]
              for i, p in enumerate(procs)]
    assert [p.returncode for p in procs] == [0] * len(procs), errors
    b = SecretServiceBackend(collection=collection["label"], address=BUS or None)
    try:
        assert len(b._find(Ref("kc-it", f"race-{round_}"))) == 1
    finally:
        b.delete(Ref("kc-it", f"race-{round_}"))
        b.close()
