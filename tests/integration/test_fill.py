"""Scenario 6: `keychain fill` / `capture` in a real headless Chromium on a local login page.

The page is served over self-signed https on loopback (plain http when openssl is missing),
which `fill` accepts only with KEYCHAIN_FILL_TEST=1. The server keeps what the form posts; the
test compares it with the stored value and never prints either.
"""

from __future__ import annotations

import hmac
import json
import secrets
import sys

import pytest

from keychainlib.api import Keychain
from keychainlib.audit import Audit
from keychainlib.cdp import Cdp
from keychainlib.errors import PolicyDenied
from keychainlib.policy import Policy

from .conftest import INTEGRATION

pytestmark = INTEGRATION

TEST = {"KEYCHAIN_FILL_TEST": "1"}
CALLER = "kc-browser"


@pytest.fixture
def login(kc, site, browser):
    """A stored credential bound to the site, the fill grant for it, the login page open."""
    value = "pw-" + secrets.token_urlsafe(16) + "-ключ"
    origin = site.origin()
    assert kc("set", "kc-it/site", "--origin", origin, stdin=value.encode()).returncode == 0
    kc.policy(f'[callers.{CALLER}]\nread = ["kc-it/*"]\nfill = ["{origin}"]\napprove = false\n')
    browser.goto(site.url("localhost", "/login"))
    site.received = {}
    yield {"value": value, "origin": origin}
    kc("delete", "kc-it/site")


def fill(kc, browser, *args, extra=TEST, caller=CALLER, agent=True):
    """`keychain fill` as an agent session: fill is allowed there, printing is not."""
    return kc("fill", "kc-it/site", "--cdp", browser.cdp_url, *args, caller=caller, agent=agent, extra=extra)


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def test_password_reaches_the_server_and_nothing_else(kc, site, browser, login):
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"filled": True, "selector": "#pw", "origin": login["origin"]}
    browser.submit()
    assert same(site.received.get("pw", ""), login["value"])
    value = login["value"].encode()
    assert value not in r.stdout + r.stderr
    journal = kc.audit_text()
    assert '"op": "fill"' in journal and login["origin"] in journal
    assert login["value"] not in journal


def test_username_field(kc, site, browser, login):
    assert kc("set", "kc-it/user", "--origin", login["origin"], stdin=b"alex@example.com").returncode == 0
    try:
        r = kc(
            "fill",
            "kc-it/user",
            "--cdp",
            browser.cdp_url,
            "--selector",
            "#user",
            "--field",
            "username",
            caller=CALLER,
            agent=True,
            extra=TEST,
        )
        assert r.returncode == 0, r.stderr
        assert fill(kc, browser, "--selector", "#pw").returncode == 0
        browser.submit()
        assert site.received.get("user") == "alex@example.com"
        assert same(site.received.get("pw", ""), login["value"])
    finally:
        kc("delete", "kc-it/user")


def test_focused_field_and_target(kc, site, browser, login):
    browser.eval("document.getElementById('pw').focus()")
    r = fill(kc, browser, "--focused", "--target", browser.target)
    assert r.returncode == 0, r.stderr
    browser.submit()
    assert same(site.received.get("pw", ""), login["value"])


def test_other_host_is_refused(kc, site, browser, login):
    # The grant covers the other host too, so the credential's own origin binding refuses it.
    kc.policy(
        f'[callers.{CALLER}]\nread = ["kc-it/*"]\n'
        f'fill = ["{login["origin"]}", "{site.origin("127.0.0.1")}"]\n'
    )
    browser.goto(site.url("127.0.0.1", "/login"))
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 8 and b"belongs to" in r.stderr, r.stderr
    assert browser.eval("document.getElementById('pw').value.length") == 0


def test_cross_origin_iframe_is_refused(kc, site, browser, login):
    kc.policy(
        f'[callers.{CALLER}]\nread = ["kc-it/*"]\n'
        f'fill = ["{login["origin"]}", "{site.origin("127.0.0.1")}"]\n'
    )
    browser.goto(site.url("localhost", "/framed"))
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 8 and b"belongs to" in r.stderr, r.stderr  # the binding, not a broken chain


def test_origin_flag_only_narrows(kc, browser, login):
    r = fill(kc, browser, "--selector", "#pw", "--origin", "https://example.com")
    assert r.returncode == 8 and b"not https://example.com" in r.stderr


def test_not_a_password_field(kc, browser, login):
    r = fill(kc, browser, "--selector", "#plain")
    assert r.returncode == 8 and b"type 'text'" in r.stderr
    r = kc(
        "fill",
        "kc-it/site",
        "--cdp",
        browser.cdp_url,
        "--selector",
        "#plain",
        "--field",
        "username",
        caller=CALLER,
        agent=True,
        extra=TEST,
    )
    assert r.returncode == 8


def test_field_turning_visible_is_cleared(kc, site, browser, login):
    browser.goto(site.url("localhost", "/flip"))
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 8 and b"cleared" in r.stderr
    assert browser.eval("document.getElementById('pw').value.length") == 0


def test_css_that_unmasks_a_password_field_is_refused(kc, site, browser, login):
    browser.goto(site.url("localhost", "/unmasked"))
    r = fill(kc, browser, "--selector", "#pw")
    masking = browser.eval("getComputedStyle(document.getElementById('pw')).webkitTextSecurity")
    if masking == "none":
        assert r.returncode == 8 and b"unmasked" in r.stderr, r.stderr
        assert browser.eval("document.getElementById('pw').value.length") == 0
    else:
        # Current Chromium keeps password inputs masked whatever the page's CSS says (computed
        # `disc`), so there is nothing to refuse; the check stays for browsers that honor it.
        assert r.returncode == 0, r.stderr


def test_value_goes_to_the_checked_field_even_if_focus_moves(kc, site, browser, login):
    browser.goto(site.url("localhost", "/thief"))
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 0, r.stderr
    assert same(browser.eval("document.getElementById('pw').value"), login["value"])
    assert browser.eval("document.getElementById('decoy').value.length") == 0
    # The page's own listeners (a framework's form state) saw the value arrive.
    seen = browser.eval("window.seen")
    assert seen["input"] >= 1 and seen["change"] >= 1


def test_no_fill_grant_or_no_read_grant(kc, browser, login):
    kc.policy('[callers.kc-someone-else]\nread = ["kc-it/*"]\n')
    r = fill(kc, browser, "--selector", "#pw", caller="kc-someone-else")
    assert r.returncode == 8 and b"fill =" in r.stderr
    # a fill grant without the read right: filling is reading (the driver can read the field)
    kc.policy(f'[callers.{CALLER}]\nfill = ["{login["origin"]}"]\n')
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 8 and b"may not read" in r.stderr
    kc.policy("")
    assert fill(kc, browser, "--selector", "#pw").returncode == 8
    assert '"outcome": "PolicyDenied"' in kc.audit_text()


def test_tls_and_scheme_need_test_mode(kc, site, browser, login):
    r = fill(kc, browser, "--selector", "#pw", extra={})
    assert r.returncode == 8
    assert (b"not valid" if site.scheme == "https" else b"not https") in r.stderr


def test_missing_element_and_endpoint_errors(kc, browser, login):
    assert fill(kc, browser, "--selector", "#nope").returncode == 2
    r = kc(
        "fill", "kc-it/site", "--cdp", "http://127.0.0.1:9", "--selector", "#pw", caller=CALLER, extra=TEST
    )
    assert r.returncode == 5
    r = kc(
        "fill", "kc-it/site", "--cdp", "http://192.0.2.1:9222", "--selector", "#pw", caller=CALLER, extra=TEST
    )
    assert r.returncode == 8
    r = kc("fill", "kc-it/missing", "--cdp", browser.cdp_url, "--selector", "#pw", caller=CALLER, extra=TEST)
    assert r.returncode == 4


def test_capture_stores_the_field_bound_to_its_origin(kc, site, browser, login):
    token = "tok-" + secrets.token_urlsafe(16)
    browser.eval("document.getElementById('token').focus()")
    browser.ctl.call("Input.insertText", {"text": token}, session=browser.session)
    r = kc(
        "capture",
        "kc-it/captured",
        "--cdp",
        browser.cdp_url,
        "--selector",
        "#token",
        caller="kc-it",
        agent=True,
        extra=TEST,
    )
    try:
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout) == {"captured": True, "ref": "kc-it/captured", "origin": login["origin"]}
        assert token.encode() not in r.stdout + r.stderr
        assert token not in kc.audit_text()
        info = json.loads(kc("info", "kc-it/captured", "--json").stdout)
        assert info["origin"] == login["origin"]
        assert kc("get", "kc-it/captured", "--reveal").stdout == token.encode()
    finally:
        kc("delete", "kc-it/captured")


class PlaywrightLike:
    """A session object with ``send(method, params)``, the shape of Playwright's CDPSession."""

    def __init__(self, cdp: Cdp, session: str) -> None:
        self.cdp, self.session = cdp, session

    def send(self, method, params=None):
        return self.cdp.call(method, params, session=self.session)


class PlaywrightLikeWithEvents(PlaywrightLike):
    """…plus ``on(event, handler)``: this tab's events are handed out after each call."""

    def __init__(self, cdp: Cdp, session: str) -> None:
        super().__init__(cdp, session)
        self.handlers: dict = {}

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)

    def send(self, method, params=None):
        result = super().send(method, params)
        pending, self.cdp.events = self.cdp.events, []
        for name, event, session in pending:
            for handler in self.handlers.get(name, []) if session == self.session else []:
                handler(event)
        return result


def test_python_api_with_url_and_with_a_cdp_session(kc, collection, site, browser, login, monkeypatch):
    monkeypatch.setenv("KEYCHAIN_FILL_TEST", "1")
    entry = {"read": ["kc-it/*"], "fill": [login["origin"]], "approve": False}
    policy = Policy.from_dict({"callers": {CALLER: entry}})
    api = Keychain(CALLER, store=collection["label"], policy=policy, audit=Audit(enabled=False))
    assert api.fill("kc-it/site", browser.cdp_url, "#pw")["filled"] is True
    browser.submit()
    assert same(site.received.get("pw", ""), login["value"])

    browser.goto(site.url("localhost", "/login"))
    assert api.fill("kc-it/site", PlaywrightLike(browser.ctl, browser.session), "#pw")["filled"] is True
    browser.submit()
    assert same(site.received.get("pw", ""), login["value"])
    browser.goto(site.url("localhost", "/login"))
    with pytest.raises(PolicyDenied):
        Keychain("kc-nobody", store=collection["label"], policy=policy, audit=Audit(enabled=False)).fill(
            "kc-it/site", browser.cdp_url, "#pw"
        )


def test_python_api_session_tls_fails_closed(kc, collection, site, browser, login, monkeypatch):
    # No test mode: the self-signed loopback page must pass the real TLS check.
    if site.scheme != "https":
        pytest.skip("needs openssl for the https test page")
    monkeypatch.delenv("KEYCHAIN_FILL_TEST", raising=False)
    entry = {"read": ["kc-it/*"], "fill": [login["origin"]], "approve": False}
    policy = Policy.from_dict({"callers": {CALLER: entry}})
    api = Keychain(CALLER, store=collection["label"], policy=policy, audit=Audit(enabled=False))
    # Without on() the browser's TLS verdict cannot arrive: refused, not assumed fine.
    with pytest.raises(PolicyDenied, match="cannot verify"):
        api.fill("kc-it/site", PlaywrightLike(browser.ctl, browser.session), "#pw")
    # With on() the verdict arrives, and Chromium (started with --ignore-certificate-errors)
    # reports the self-signed certificate as invalid.
    with pytest.raises(PolicyDenied, match="not valid"):
        api.fill("kc-it/site", PlaywrightLikeWithEvents(browser.ctl, browser.session), "#pw")
    assert browser.eval("document.getElementById('pw').value.length") == 0


def test_the_human_approves_through_the_configured_command(kc, site, browser, login, tmp_path):
    """The approval channel is a command from the policy file: exit 0 fills, anything else stops
    the fill before the store is read, and the prompt it is given names the ref and origin."""
    seen = tmp_path / "seen.txt"
    verdict = tmp_path / "verdict"
    command = tmp_path / "approver.py"
    command.write_text(
        "import os, sys\n"
        f"open({str(seen)!r}, 'w').write(sys.argv[1] + '|' + os.environ['KEYCHAIN_APPROVAL_TIMEOUT'])\n"
        f"sys.exit(0 if os.path.exists({str(verdict)!r}) else 1)\n"
    )
    kc.policy(
        f"approval_cmd = [{sys.executable!r}, {str(command)!r}]\napproval_timeout = 60\n"
        f'[callers.{CALLER}]\nread = ["kc-it/*"]\nfill = ["{login["origin"]}"]\n'
    )
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 8 and b"did not approve" in r.stderr, r.stderr
    assert browser.eval("document.getElementById('pw').value.length") == 0
    prompt, timeout = seen.read_text().rsplit("|", 1)
    assert "kc-it/site" in prompt and login["origin"] in prompt and timeout == "60"
    verdict.write_text("")
    r = fill(kc, browser, "--selector", "#pw")
    assert r.returncode == 0, r.stderr
    browser.submit()
    assert same(site.received.get("pw", ""), login["value"])
    assert '"approval": "approved"' in kc.audit_text() and login["value"] not in kc.audit_text()
