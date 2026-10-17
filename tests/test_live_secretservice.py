"""Live checks against the real Secret Service (gnome-keyring). Opt-in: KEYCHAIN_LIVE=1.

Each run creates a throwaway collection with a known password through gnome-keyring's
master-password interface, works only inside it, and deletes it afterwards; the user's login
keyring is never written.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from keychainlib.backends.dbus import Variant
from keychainlib.backends.secretservice import COLLECTION, GNOME, SERVICE, SERVICE_PATH, SecretServiceBackend
from keychainlib.errors import Locked
from keychainlib.refs import Ref

from .conftest import scrubbed_env

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("KEYCHAIN_LIVE") != "1" or sys.platform != "linux",
        reason="live Secret Service test: set KEYCHAIN_LIVE=1 on Linux",
    ),
]

BIN = Path(__file__).resolve().parent.parent / "bin" / "keychain"
VALUE = "live-" + secrets.token_urlsafe(18)


@pytest.fixture(scope="module")
def collection():
    label = f"keychain-cli-test-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(12).encode()
    b = SecretServiceBackend()
    path = b._call(
        SERVICE_PATH,
        GNOME,
        "CreateWithMasterPassword",
        "a{sv}(oayays)",
        [{f"{COLLECTION}.Label": Variant("s", label)}, b._secret_struct(password)],
    )[0]
    yield {"label": label, "path": path, "password": password, "backend": b}
    b._call(path, COLLECTION, "Delete")
    b.close()


def cli(args, label, stdin=None, agent=False, caller=None):
    """Run the installed-style entry point (its `-I` shebang included) as a human, or as an
    agent session with ``agent=True``."""
    env = {**scrubbed_env(os.environ), "KEYCHAIN_STORE": label}
    if agent:
        env["KEYCHAIN_AGENT"] = "1"
    if caller:
        env["KEYCHAIN_CALLER"] = caller
    return subprocess.run(
        [str(BIN), *args], input=stdin, capture_output=True, env=env, timeout=60, check=False
    )


def test_set_get_exec_delete(collection):
    label = collection["label"]
    r = cli(
        ["set", "kc-live/token", "--label", "live test", "--note", "pytest"],
        label,
        stdin=VALUE.encode() + b"\n",
    )
    assert r.returncode == 0, r.stderr
    r = cli(["get", "kc-live/token", "--reveal"], label)
    assert (r.returncode, r.stdout) == (0, VALUE.encode())
    r = cli(["info", "kc-live/token", "--json"], label)
    assert b'"label": "live test"' in r.stdout and VALUE.encode() not in r.stdout
    r = cli(["list", "kc-live"], label)
    assert b"kc-live/token" in r.stdout and VALUE.encode() not in r.stdout
    code = f"import os; assert os.environ['T'] == {VALUE!r}; print(os.environ['T'])"
    r = cli(["exec", "--env", "T=kc-live/token", "--", sys.executable, "-c", code], label)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == b"***"
    # update keeps exactly one item and the label
    assert cli(["set", "kc-live/token"], label, stdin=b"second-value").returncode == 0
    assert cli(["get", "kc-live/token", "--reveal"], label).stdout == b"second-value"
    assert len(collection["backend"].list("kc-live")) == 0  # other collection: login is untouched
    # agent session: neither the default caller nor a claimed utility name may print...
    assert cli(["get", "kc-live/token", "--reveal"], label, agent=True).returncode == 8
    assert cli(["get", "kc-live/token", "--reveal"], label, agent=True, caller="kc-live").returncode == 8
    # ...until the human grants it
    policy = Path(os.environ["XDG_CONFIG_HOME"]) / "keychain-cli" / "policy.toml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("[callers.kc-live]\nreveal = true\n")
    r = cli(["get", "kc-live/token", "--reveal"], label, agent=True, caller="kc-live")
    assert (r.returncode, r.stdout) == (0, b"second-value")
    policy.unlink()
    # our item addressed by its raw id must not bypass the namespace check
    b = SecretServiceBackend(collection=label)
    item_id = b._find(Ref("kc-live", "token"))[0].split("/collection/", 1)[1]
    b.close()
    r = cli(["system", "get", item_id, "--reveal"], label)
    assert r.returncode == 2 and b"second-value" not in r.stdout + r.stderr
    assert cli(["delete", "kc-live/token"], label).returncode == 0
    assert cli(["exists", "kc-live/token"], label).returncode == 4


def test_locked_fails_fast_then_tty_unlock(collection, monkeypatch):
    b = SecretServiceBackend(collection=collection["label"], interactive=False)
    b.set(Ref("kc-live", "lock"), b"locked-value", None, None)
    b._call(SERVICE_PATH, SERVICE, "Lock", "ao", [[collection["path"]]])
    r = cli(["get", "kc-live/lock", "--reveal", "--no-prompt"], collection["label"])
    assert r.returncode == 9, r.stderr
    assert b"keychain unlock" in r.stderr
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": "wrong")
    with pytest.raises(Locked):
        b.unlock()
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": collection["password"].decode())
    assert "unlocked" in b.unlock()
    assert b.get(Ref("kc-live", "lock")) == b"locked-value"
    b.delete(Ref("kc-live", "lock"))
    b.close()


def test_concurrent_writers_converge_on_one_item(collection):
    """Ten processes setting the same new ref at once: all succeed and one item remains."""
    label = collection["label"]
    env = {**scrubbed_env(os.environ), "KEYCHAIN_STORE": label}
    procs = [subprocess.Popen([str(BIN), "set", "kc-live/race"], stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
             for _ in range(10)]
    errors = [p.communicate(f"race-value-{i}".encode(), timeout=60)[1] for i, p in enumerate(procs)]
    assert [p.returncode for p in procs] == [0] * 10, errors
    b = SecretServiceBackend(collection=label)
    assert len(b._find(Ref("kc-live", "race"))) == 1
    assert b.get(Ref("kc-live", "race")).startswith(b"race-value-")
    b.delete(Ref("kc-live", "race"))
    b.close()
