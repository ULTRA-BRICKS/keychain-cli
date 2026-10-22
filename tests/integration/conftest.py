"""Integration fixtures: the real `bin/keychain`, a real gnome-keyring collection, real Chromium.

Opt-in with ``KEYCHAIN_INTEGRATION=1`` on Linux. The tests need a session bus with a running
gnome-keyring (a desktop login, or `dbus-run-session` + `gnome-keyring-daemon --unlock` as
CI does). Each run creates a throwaway collection and deletes it afterwards; the user's
login keyring, policy file and audit journal are never touched.
"""

from __future__ import annotations

import glob
import http.server
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

from keychainlib.backends.dbus import Variant
from keychainlib.backends.secretservice import COLLECTION, GNOME, SERVICE_PATH, SecretServiceBackend

from ..conftest import scrubbed_env

ENABLED = os.environ.get("KEYCHAIN_INTEGRATION") == "1" and sys.platform.startswith("linux")
ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "bin" / "keychain"


# Every integration module sets `pytestmark = INTEGRATION`.
INTEGRATION = [
    pytest.mark.integration,
    pytest.mark.skipif(not ENABLED, reason="integration test: set KEYCHAIN_INTEGRATION=1 on Linux"),
]


# The bus the tests (and the binaries they start) talk to: captured before the autouse fixture
# in tests/conftest.py scrubs the environment.
BUS = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")


@pytest.fixture(scope="session")
def collection():
    label = f"keychain-cli-it-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(12)
    b = SecretServiceBackend(address=BUS or None)
    path = b._call(
        SERVICE_PATH,
        GNOME,
        "CreateWithMasterPassword",
        "a{sv}(oayays)",
        [{f"{COLLECTION}.Label": Variant("s", label)}, b._secret_struct(password.encode())],
    )[0]
    yield {"label": label, "path": path, "password": password, "backend": b}
    b._call(path, COLLECTION, "Delete")
    b.close()


class Runner:
    """Runs `bin/keychain` (its `python3 -I` shebang included) against the test collection."""

    def __init__(self, label: str, home: Path) -> None:
        self.label = label
        self.config = home / "config"
        self.state = home / "state"

    def env(self, *, agent: bool = False, caller: str | None = None, extra: dict | None = None) -> dict:
        env = {
            **scrubbed_env(os.environ),
            "KEYCHAIN_STORE": self.label,
            "XDG_CONFIG_HOME": str(self.config),
            "XDG_STATE_HOME": str(self.state),
        }
        if BUS:
            env["DBUS_SESSION_BUS_ADDRESS"] = BUS
        if agent:
            env["KEYCHAIN_AGENT"] = "1"
        if caller:
            env["KEYCHAIN_CALLER"] = caller
        env.update(extra or {})
        return env

    def __call__(self, *args: str, stdin: bytes | None = None, **kw) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(BIN), *args], input=stdin, capture_output=True, env=self.env(**kw), timeout=90, check=False
        )

    def policy(self, text: str) -> None:
        path = self.config / "keychain-cli" / "policy.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def audit_text(self) -> str:
        path = self.state / "keychain-cli" / "audit.jsonl"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def kc(collection, tmp_path) -> Runner:
    return Runner(collection["label"], tmp_path)


# ── a local login site ───────────────────────────────────────────────────────

LOGIN = """<!doctype html><meta charset=utf-8><title>login</title>
<form method=post action=/submit>
<input type=email id=user name=user autocomplete=username>
<input type=password id=pw name=pw autocomplete=current-password>
<input type=text id=plain name=plain>
<input type=text id=token name=token>
<button>Sign in</button></form>"""
FLIP = """<!doctype html><meta charset=utf-8>
<input type=password id=pw>
<script>pw.addEventListener('input', () => { pw.type = 'text'; });</script>"""
UNMASKED = """<!doctype html><meta charset=utf-8>
<input type=password id=pw style="-webkit-text-security: none">"""
# Moves focus to a decoy right after the password field gets it, and counts the events a page
# framework listens to: the value must still land in #pw, and the page must see it arrive.
THIEF = """<!doctype html><meta charset=utf-8>
<input type=password id=pw><input type=text id=decoy>
<script>
window.seen = {input: 0, change: 0};
pw.addEventListener('focus', () => setTimeout(() => decoy.focus(), 0));
pw.addEventListener('input', () => { seen.input++; });
pw.addEventListener('change', () => { seen.change++; });
</script>"""


class Site:
    def __init__(self) -> None:
        self.received: dict[str, str] = {}
        self.scheme = "http"
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):  # never echo a request (the POST carries the value)
                pass

            def do_GET(self):
                if self.path == "/framed":
                    body = f"<!doctype html><iframe src='{site.url('127.0.0.1', '/login')}'></iframe>"
                elif self.path == "/flip":
                    body = FLIP
                elif self.path == "/unmasked":
                    body = UNMASKED
                elif self.path == "/thief":
                    body = THIEF
                else:
                    body = LOGIN
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
                site.received = {k: v[0] for k, v in form.items()}
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self._tls()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _tls(self) -> None:
        """Self-signed https when openssl is available (plain http otherwise; both are allowed
        for loopback pages only under KEYCHAIN_FILL_TEST=1)."""
        if not shutil.which("openssl"):
            return
        d = Path(tempfile.mkdtemp(prefix="kc-it-tls-"))
        try:
            r = subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                 "-subj", "/CN=localhost", "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem"),
                 "-addext", "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"],
                capture_output=True, check=False,
            )
            if r.returncode != 0:
                return
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(d / "cert.pem", d / "key.pem")  # read now: the files can go
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.scheme = "https"

    def origin(self, host: str = "localhost") -> str:
        return f"{self.scheme}://{host}:{self.port}"

    def url(self, host: str, path: str) -> str:
        return self.origin(host) + path


@pytest.fixture(scope="session")
def site():
    s = Site()
    yield s
    s.server.shutdown()


# ── Chromium ─────────────────────────────────────────────────────────────────


def find_chromium() -> str | None:
    explicit = os.environ.get("KEYCHAIN_TEST_CHROME")
    if explicit:
        return explicit
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    found = glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome"))
    # The newest build: chromium-1248 sorts before chromium-999 as text.
    return max(found, key=lambda p: int(re.search(r"chromium-(\d+)", p).group(1)), default=None)


class Browser:
    def __init__(self, binary: str) -> None:
        from keychainlib.cdp import Cdp

        self.profile = Path(tempfile.mkdtemp(prefix="kc-it-chrome-"))
        args = [
            binary, "--headless=new", "--remote-debugging-port=0", f"--user-data-dir={self.profile}",
            "--no-first-run", "--no-default-browser-check", "--ignore-certificate-errors",
            "--disable-features=Translate,MediaRouter", "about:blank",
        ]
        if os.geteuid() == 0 or os.environ.get("KEYCHAIN_TEST_CHROME_NO_SANDBOX") == "1":
            args.insert(1, "--no-sandbox")  # root in a CI container has no usable sandbox
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port_file = self.profile / "DevToolsActivePort"
        for _ in range(300):
            if port_file.exists() and len(port_file.read_text().split()) == 2:
                break
            if self.proc.poll() is not None:
                raise RuntimeError(f"Chromium exited with {self.proc.returncode}")
            time.sleep(0.1)
        else:
            raise RuntimeError("Chromium did not open its DevTools port")
        port = port_file.read_text().split()[0]
        self.cdp_url = f"http://127.0.0.1:{port}"
        self.ctl = Cdp.connect(self.cdp_url)
        pages = [t for t in self.ctl.call("Target.getTargets")["targetInfos"] if t["type"] == "page"]
        self.target = pages[0]["targetId"]
        self.session = self.ctl.call("Target.attachToTarget", {"targetId": self.target, "flatten": True})[
            "sessionId"
        ]

    def eval(self, expression: str):
        r = self.ctl.call(
            "Runtime.evaluate", {"expression": expression, "returnByValue": True}, session=self.session
        )
        return r.get("result", {}).get("value")

    def goto(self, url: str) -> None:
        self.ctl.call("Page.navigate", {"url": url}, session=self.session)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            time.sleep(0.1)
            if self.eval("document.readyState + ' ' + location.href") == f"complete {url}":
                frames = self.eval("document.querySelectorAll('iframe').length") or 0
                time.sleep(0.5 if frames else 0.05)  # let iframes load
                return
        raise RuntimeError(f"page did not load: {url}")

    def submit(self) -> None:
        self.eval("document.forms[0].submit()")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and self.eval("location.pathname") != "/submit":
            time.sleep(0.05)
        time.sleep(0.1)

    def close(self) -> None:
        self.ctl.close()
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


@pytest.fixture(scope="session")
def browser():
    binary = find_chromium()
    if binary is None:
        pytest.skip("no Chromium/Chrome found (set KEYCHAIN_TEST_CHROME): fill tests need a real browser")
    b = Browser(binary)
    yield b
    b.close()
