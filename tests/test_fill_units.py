"""Origins, the fill grant, the CDP endpoint rules and the WebSocket client, without a browser
(the browser itself is exercised in tests/integration/test_fill.py)."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import sys
import threading
from dataclasses import replace

import pytest

from keychainlib import browser
from keychainlib import cdp as cdp_mod
from keychainlib.api import Keychain
from keychainlib.audit import Audit
from keychainlib.backends.fake import FakeBackend
from keychainlib.backends.macos import parse_items
from keychainlib.context import USER
from keychainlib.errors import BackendError, BackendUnavailable, Locked, NotFound, PolicyDenied, UsageError
from keychainlib.origins import (
    Origin,
    binds,
    check_scheme,
    normalize_origin,
    normalize_origin_pattern,
    parse_origin,
)
from keychainlib.policy import Policy
from keychainlib.refs import parse_item_ref

from .conftest import SECRET


def test_parse_and_normalize_origin():
    assert parse_origin("https://Login.Site.TLD:443/path?q#f") == Origin("https", "login.site.tld", 443)
    assert str(parse_origin("http://localhost:8080/x")) == "http://localhost:8080"
    assert parse_origin("about:blank") is None and parse_origin("data:text/html,x") is None
    assert normalize_origin("https://github.com/login") == "https://github.com"
    for bad in ("github.com", "ftp://x", "https://user:pw@site.tld", "https://:1"):
        with pytest.raises(UsageError):
            normalize_origin(bad)


@pytest.mark.parametrize(
    ("record", "frame", "ok"),
    [
        ("https://site.tld", "https://site.tld/login", True),
        ("https://site.tld", "https://login.site.tld", True),
        ("https://site.tld", "https://evilsite.tld", False),
        ("https://site.tld", "https://site.tld.evil.com", False),
        ("https://login.site.tld", "https://site.tld", False),
        ("https://site.tld", "http://site.tld", False),
        ("https://site.tld", "https://site.tld:8443", False),
    ],
)
def test_binding(record, frame, ok):
    assert binds(parse_origin(record), parse_origin(frame)) is ok


def test_binding_without_subdomains_is_the_exact_host():
    record = parse_origin("https://site.tld")
    assert binds(record, parse_origin("https://site.tld/login"), subdomains=False)
    assert not binds(record, parse_origin("https://login.site.tld"), subdomains=False)


def test_internationalized_hosts_are_punycode():
    # The browser reports frame URLs in punycode; a credential bound to the Unicode name must match.
    assert parse_origin("https://Bücher.de/x") == Origin("https", "xn--bcher-kva.de", 443)
    assert normalize_origin("https://bücher.de") == "https://xn--bcher-kva.de"


@pytest.mark.parametrize(
    ("grant", "normalized"),
    [
        ("https://GitHub.com", "https://github.com"),
        ("https://github.com/", "https://github.com"),
        ("https://github.com:443", "https://github.com"),
        ("http://localhost:80", "http://localhost"),
        ("https://*.Site.tld", "https://*.site.tld"),
        ("https://localhost:8443", "https://localhost:8443"),
        ("https://bücher.de", "https://xn--bcher-kva.de"),
    ],
)
def test_fill_grants_are_normalized(grant, normalized):
    assert normalize_origin_pattern(grant) == normalized
    assert Policy.from_dict({"callers": {"ba": {"fill": [grant]}}}).callers["ba"].fill == (normalized,)


@pytest.mark.parametrize(
    "grant", ["github.com", "https://github.com/login", "https://u@github.com", "https://"]
)
def test_a_fill_grant_that_is_no_origin_is_rejected(grant):
    with pytest.raises(UsageError):
        Policy.from_dict({"callers": {"ba": {"fill": [grant]}}})


@pytest.mark.parametrize("host", ["faß.de", "ﬁle.de", "a\u200db.de"])
def test_a_host_punycode_would_change_is_refused(host):
    # Python's IDNA2003 would turn faß.de into fass.de, someone else's domain; browsers do not.
    assert parse_origin(f"https://{host}/") is None
    with pytest.raises(UsageError):
        normalize_origin(f"https://{host}")
    with pytest.raises(UsageError):
        normalize_origin_pattern(f"https://{host}")


def test_an_ipv6_fill_grant_matches_its_page():
    policy = Policy.from_dict({"callers": {"ba": {"fill": ["https://[::1]:8443"]}}})
    assert policy.allows_fill("ba", str(parse_origin("https://[::1]:8443/login")))
    assert not policy.allows_fill("ba", "https://[::2]:8443")


def test_scheme_rules(monkeypatch):
    assert check_scheme(parse_origin("https://site.tld")).host == "site.tld"
    with pytest.raises(PolicyDenied):
        check_scheme(parse_origin("http://site.tld"))
    with pytest.raises(PolicyDenied):
        check_scheme(parse_origin("http://localhost:8000"))
    with pytest.raises(PolicyDenied):
        check_scheme(None, "chrome://settings")
    monkeypatch.setenv("KEYCHAIN_FILL_TEST", "1")
    assert check_scheme(parse_origin("http://localhost:8000")).loopback
    assert check_scheme(parse_origin("http://127.0.0.1:8000")).loopback
    with pytest.raises(PolicyDenied):  # test mode never relaxes a real host
        check_scheme(parse_origin("http://site.tld"))


def test_fill_grant():
    policy = Policy.from_dict({"callers": {"ba": {"fill": ["https://github.com", "https://*.site.tld"]}}})
    assert policy.allows_fill("ba", "https://github.com")
    assert policy.allows_fill("ba", "https://login.site.tld")
    assert not policy.allows_fill("ba", "https://site.tld")
    assert not policy.allows_fill("ba", "https://github.com.evil.tld")
    assert not policy.allows_fill("ba", "http://github.com")
    assert not policy.allows_fill("agent", "https://github.com")
    assert not policy.allows_fill("ba-other", "https://github.com")
    assert policy.allows_fill("user", "https://anything.tld")
    with pytest.raises(PolicyDenied) as exc:
        policy.check_fill("ba", "https://gitlab.com")
    assert 'fill = ["https://gitlab.com"]' in exc.value.fix
    with pytest.raises(UsageError):
        Policy.from_dict({"callers": {"ba": {"fill": "https://github.com"}}})


def test_owning_a_namespace_does_not_grant_fill():
    assert not Policy().allows_fill("tool", "https://site.tld")


@pytest.mark.parametrize("url", ["http://192.0.2.1:9222", "ws://example.com:9222/devtools/browser/x"])
def test_cdp_endpoint_must_be_loopback(url):
    with pytest.raises(PolicyDenied):
        cdp_mod._browser_ws_url(url)


@pytest.mark.parametrize("url", ["https://127.0.0.1:9222", "127.0.0.1:9222", "ws://127.0.0.1/x"])
def test_cdp_endpoint_shape(url):
    with pytest.raises(UsageError):
        cdp_mod._browser_ws_url(url)


def test_cdp_endpoint_down_is_unavailable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(BackendUnavailable):
        cdp_mod._browser_ws_url(f"http://127.0.0.1:{port}")


class FakeBrowser:
    """A one-connection WebSocket server speaking just enough CDP for the client tests."""

    def __init__(self, replies) -> None:
        self.replies = replies
        self.received: list[dict] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _send(self, conn, text: str) -> None:
        data = text.encode()
        if len(data) < 126:
            header = struct.pack("!BB", 0x81, len(data))
        else:
            header = struct.pack("!BBQ", 0x81, 127, len(data))
        conn.sendall(header + data)

    def _recv(self, conn) -> dict:
        _b0, b1 = conn.recv(2, socket.MSG_WAITALL)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack("!H", conn.recv(2, socket.MSG_WAITALL))[0]
        elif n == 127:
            n = struct.unpack("!Q", conn.recv(8, socket.MSG_WAITALL))[0]
        mask = conn.recv(4, socket.MSG_WAITALL)
        payload = conn.recv(n, socket.MSG_WAITALL) if n else b""
        return json.loads(bytes(c ^ mask[i & 3] for i, c in enumerate(payload)))

    def _serve(self) -> None:
        conn, _ = self.listener.accept()
        head = b""
        while b"\r\n\r\n" not in head:
            head += conn.recv(1024)
        key = next(
            line.split(":", 1)[1].strip()
            for line in head.decode().split("\r\n")
            if line.lower().startswith("sec-websocket-key")
        )
        accept = base64.b64encode(hashlib.sha1((key + cdp_mod._WS_GUID).encode()).digest()).decode()
        conn.sendall(
            f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode()
        )
        for reply in self.replies:
            msg = self._recv(conn)
            self.received.append(msg)
            for out in reply(msg):
                self._send(conn, json.dumps(out))


def test_websocket_cdp_roundtrip_events_and_errors():
    big = "x" * 70000
    server = FakeBrowser(
        [
            lambda m: [
                {"method": "Target.attachedToTarget", "params": {"n": 1}, "sessionId": "S"},
                {"id": m["id"], "result": {"ok": big}},
            ],
            lambda m: [{"id": m["id"], "error": {"message": "No node with given id"}}],
        ]
    )
    c = cdp_mod.Cdp.connect(f"ws://127.0.0.1:{server.port}/devtools/browser/x")
    try:
        assert c.call("A.b", {"secret-param": "s3cr3t"}, session="S")["ok"] == big
        assert c.take_events("Target.attachedToTarget", None) == []  # it arrived on session S
        assert c.take_events("Target.attachedToTarget", "S") == [({"n": 1}, "S")]
        with pytest.raises(cdp_mod.CdpCallError) as exc:
            c.call("DOM.describeNode", {"secret-param": "s3cr3t"})
        assert "s3cr3t" not in exc.value.render()
    finally:
        c.close()
    assert server.received[0]["sessionId"] == "S" and server.received[0]["method"] == "A.b"


def test_peer_owner_check_accepts_our_own_listener():
    server = FakeBrowser([])
    c = cdp_mod.Cdp.connect(f"ws://127.0.0.1:{server.port}/x")
    c.close()


def test_session_adapter_rejects_other_targets():
    adapter = cdp_mod.SessionCdp(lambda method, params: {"echo": method})
    assert adapter.call("Page.getFrameTree") == {"echo": "Page.getFrameTree"}
    with pytest.raises(UsageError):
        adapter.call("Page.getFrameTree", session="other")


def test_session_adapter_needs_on_for_events():
    assert cdp_mod.SessionCdp(lambda method, params: {}).watch(browser._SECURITY_EVENT) is False
    handlers: dict = {}
    adapter = cdp_mod.SessionCdp(
        lambda method, params: {}, lambda event, h: handlers.setdefault(event, []).append(h)
    )
    assert adapter.watch("A.e") and adapter.watch("A.e")
    assert len(handlers["A.e"]) == 1  # subscribed once
    handlers["A.e"][0]({"n": 1})
    assert adapter.take_events("A.e") == [({"n": 1}, None)] and adapter.take_events("A.e") == []
    adapter.close()  # the caller's session keeps our handler; it must stop collecting
    handlers["A.e"][0]({"n": 2})
    assert adapter.take_events("A.e") == []


@pytest.mark.skipif(sys.byteorder != "little", reason="/proc/net/tcp words are in host byte order")
@pytest.mark.parametrize(
    ("field", "address", "port"),
    [
        ("0100007F:1F90", "127.0.0.1", 8080),
        ("00000000000000000000000001000000:0016", "::1", 22),
        # what a dual-stack listener on `::` shows for our IPv4 connection
        ("0000000000000000FFFF00000100007F:A3E1", "127.0.0.1", 41953),
    ],
)
def test_proc_net_tcp_endpoint_decoding(field, address, port):
    import ipaddress

    assert cdp_mod._proc_endpoint(field) == (ipaddress.ip_address(address), port)


# ── fill/capture logic against a scripted page (no browser) ──────────────────


class FakePage:
    """One page as Playwright's CDPSession sees it: ``send(method, params)`` and
    ``on(event, handler)``. It plays a login page at ``url`` whose ``#pw`` is ``describe``."""

    def __init__(self, url: str = "https://site.tld/login", *, security="secure", describe=None, after=None):
        self.url = url
        self.security = security
        self.describe = {
            "tag": "INPUT",
            "type": "password",
            "disabled": False,
            "readOnly": False,
            "connected": True,
            "visibility": "visible",
            "masking": "disc",
            "autocomplete": "",
            **(describe or {}),
        }
        self.after = after or {}
        self.handlers: dict = {}
        self.sent: list[str] = []
        self.value: str | None = None
        self.write_allowed = True  # the in-browser pre-write check of `_WRITE`

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)

    def send(self, method, params=None):
        params = params or {}
        self.sent.append(method)
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "M", "url": self.url}}}
        if method == "Page.createIsolatedWorld":
            return {"executionContextId": 7}
        if method == "Runtime.evaluate":
            return {"result": {"objectId": "pw-1", "subtype": "node"}}
        if method == "DOM.getBoxModel":
            return {"model": {"width": 120, "height": 20}}
        if method == "Security.enable" and self.security is not None:
            for handler in self.handlers.get(browser._SECURITY_EVENT, []):
                handler({"visibleSecurityState": {"securityState": self.security}})
        if method == "Runtime.callFunctionOn":
            assert params["objectId"] == "pw-1"  # always the element that was checked
            return {
                "result": {
                    "value": self.function(
                        params["functionDeclaration"], [a["value"] for a in params["arguments"]]
                    )
                }
            }
        return {}

    def function(self, fn: str, args: list):
        if fn == browser._DESCRIBE:
            return self.describe
        if fn == browser._FOCUS:
            return True
        if fn == browser._WRITE:
            if not self.write_allowed:
                return False
            self.value = args[0]
            return True
        if fn == browser._AFTER:
            complete = self.value is not None and browser.utf16_len(self.value) == args[0]
            return {
                "type": "password",
                "complete": complete,
                "connected": True,
                "masking": "disc",
                **self.after,
            }
        if fn == browser._CLEAR:
            self.value = ""
            return None
        if fn == browser._VALUE:
            return self.value
        raise AssertionError(fn)


class SendOnly:
    """A session object without ``on``: no events, so no TLS verdict."""

    def __init__(self, page: FakePage) -> None:
        self.send = page.send


REF = "ba/site"


class LockedHidesItems(FakeBackend):
    """Like a collection loaded locked: its items' attributes are not readable until unlocked,
    so a lookup by ref finds nothing."""

    def info(self, ref):
        if self.locked:
            raise NotFound(f"no secret {ref}")
        return super().info(ref)

    def system_info(self, ident):
        item = super().system_info(ident)
        return replace(item, attributes={}) if self.locked else item


def keychain(caller: str, grants: dict | None = None, origin: str = "https://site.tld") -> Keychain:
    backend = LockedHidesItems()
    backend.set(parse_item_ref(REF), SECRET.encode(), None, None, origin=origin)
    entries = {"ba": {"fill": ["https://site.tld"]}, **(grants or {})}
    # Approval has its own tests (test_approval.py); here every caller is released from asking.
    policy = Policy.from_dict({"callers": {n: {"approve": False, **e} for n, e in entries.items()}})
    return Keychain(caller, backend=backend, policy=policy, audit=Audit(enabled=False))


def test_fill_writes_the_value_into_the_checked_element():
    page = FakePage()
    assert keychain("ba").fill(REF, page, "#pw") == {
        "filled": True,
        "selector": "#pw",
        "origin": "https://site.tld",
    }
    assert page.value == SECRET
    # Typed text would go to whatever has focus when it lands; the value is set on the element.
    assert "Input.insertText" not in page.sent and "Input.dispatchKeyEvent" not in page.sent


def test_fill_needs_the_read_right_too():
    page = FakePage()
    other = keychain("bb", {"bb": {"fill": ["https://site.tld"]}})
    with pytest.raises(PolicyDenied, match="may not read"):
        other.fill(REF, page, "#pw")
    assert page.sent == []  # refused before the browser (or the store) is touched
    granted = keychain("bb", {"bb": {"fill": ["https://site.tld"], "read": [REF]}})
    assert granted.fill(REF, page, "#pw")["filled"] is True


def test_user_without_a_grant_gets_the_exact_host_only():
    page = FakePage("https://login.site.tld/")
    with pytest.raises(PolicyDenied, match="belongs to"):
        keychain(USER).fill(REF, page, "#pw")
    assert page.value is None
    granted = keychain("ba", {"ba": {"fill": ["https://login.site.tld"]}})
    assert granted.fill(REF, page, "#pw")["origin"] == "https://login.site.tld"


@pytest.mark.parametrize(
    ("session", "message"),
    [
        (lambda page: SendOnly(page), "cannot verify the TLS state"),
        (lambda page: page, "not valid"),
    ],
)
def test_tls_state_fails_closed(session, message):
    page = FakePage(security="insecure")
    with pytest.raises(PolicyDenied, match=message):
        keychain("ba").fill(REF, session(page), "#pw")
    assert page.value is None


@pytest.mark.parametrize(
    ("describe", "after", "error", "message"),
    [
        ({"masking": "none"}, {}, PolicyDenied, "unmasked"),
        ({}, {"masking": "none"}, PolicyDenied, "cleared"),
        ({}, {"type": "text"}, PolicyDenied, "cleared"),
        ({}, {"complete": False}, BackendError, "cleared"),
    ],
)
def test_unsafe_field_is_refused_or_cleared(describe, after, error, message):
    page = FakePage(describe=describe, after=after)
    with pytest.raises(error, match=message):
        keychain("ba").fill(REF, page, "#pw")
    assert page.value in (None, "")


class FrameTrees:
    """Page.getFrameTree answers per session, for the frame-chain rules."""

    supports_sessions = False

    def __init__(self, trees: dict) -> None:
        self.trees = trees

    def call(self, method, params=None, session=None):
        assert method == "Page.getFrameTree"
        tree = self.trees[session]
        if isinstance(tree, Exception):
            raise tree
        return {"frameTree": tree}


def tree(frame_id: str, url: str, *children, parent: str | None = None) -> dict:
    frame = {"id": frame_id, "url": url, **({"parentId": parent} if parent else {})}
    return {"frame": frame, "childFrames": list(children)}


def test_frame_chain_reaches_the_top():
    frames = tree("M", "https://a.tld", tree("C", "https://a.tld/f", parent="M"))
    page = browser.PageTarget(FrameTrees({None: frames}), None)
    assert [f.id for f in page.chain("C")] == ["C", "M"]


def test_frame_chain_with_a_gap_is_refused():
    # The iframe's own session answers, the session holding its parent does not.
    trees = {
        None: tree("M", "https://a.tld"),
        "S1": cdp_mod.CdpCallError("Page.getFrameTree", "gone"),
        "S2": tree("I", "https://b.tld"),
    }
    page = browser.PageTarget(FrameTrees(trees), None)
    page.children = ["S1", "S2"]
    with pytest.raises(PolicyDenied, match="top frame"):
        page.chain("I")
    with pytest.raises(PolicyDenied, match="cannot resolve"):
        page.chain("unknown")


def test_frame_chain_too_deep_is_refused():
    node = tree("F20", "https://a.tld", parent="F19")
    for i in range(19, 0, -1):
        node = tree(f"F{i}", "https://a.tld", node, parent=f"F{i - 1}")
    page = browser.PageTarget(FrameTrees({None: tree("F0", "https://a.tld", node)}), None)
    with pytest.raises(PolicyDenied, match="cannot resolve"):
        page.chain("F20")


def test_fill_on_a_locked_store_is_locked_not_missing():
    kc = keychain("ba")
    kc.backend.locked = True
    page = FakePage()
    with pytest.raises(Locked):  # exit 9 "unlock it", never exit 4 "store it again"
        kc.fill(REF, page, "#pw")
    assert page.value is None


def test_capture_never_rebinds_another_sites_item():
    kc = keychain("ba")
    page = FakePage("https://other.tld/signup", describe={"type": "text"})
    page.value = "captured-" + "x" * 8
    with pytest.raises(PolicyDenied, match="refusing to overwrite"):
        kc.capture(REF, page, "#token")
    assert kc.backend.get(parse_item_ref(REF)) == SECRET.encode()
    assert kc.backend.info(parse_item_ref(REF)).origin == "https://site.tld"
    same_site = FakePage("https://site.tld/settings", describe={"type": "text"})
    same_site.value = page.value
    assert kc.capture(REF, same_site, "#token") == {
        "captured": True,
        "ref": REF,
        "origin": "https://site.tld",
    }
    assert kc.backend.get(parse_item_ref(REF)) == page.value.encode()


def test_capture_on_a_locked_store_does_not_skip_the_overwrite_check():
    kc = keychain("ba")
    kc.backend.locked = True
    with pytest.raises(Locked):
        kc.capture(REF, FakePage("https://other.tld/", describe={"type": "text"}), "#token")


def test_macos_internet_password_is_bound_to_its_server():
    dump = (
        'class: "inet"\nattributes:\n'
        '    "acct"<blob>="alex"\n'
        '    "port"<uint32>=0x00000000 \n'
        '    "ptcl"<uint32>="htps"\n'
        '    "srvr"<blob>="github.com"\n'
    )
    attrs = parse_items(dump)[0]["attrs"]
    assert (attrs["ptcl"], attrs["port"], attrs["srvr"]) == ("htps", "0", "github.com")
    backend = FakeBackend()
    backend.add_system("inet:github.com/alex", SECRET.encode(), "github.com", attrs)
    kc = Keychain(USER, backend=backend, policy=Policy(), audit=Audit(enabled=False))
    page = FakePage("https://github.com/login")
    assert kc.fill("system:inet:github.com/alex", page, "#pw")["origin"] == "https://github.com"
    assert page.value == SECRET


def test_system_item_url_first_one_that_parses():
    backend = FakeBackend()
    backend.add_system("x", SECRET.encode(), "x", {"url": "github.com", "origin_url": "https://github.com/"})
    kc = Keychain(USER, backend=backend, policy=Policy(), audit=Audit(enabled=False))
    page = FakePage("https://github.com/login")
    assert kc.fill("system:x", page, "#pw")["filled"] is True


class Tabs:
    """A browser with two tabs, one of which closes before we attach to it."""

    supports_sessions = True

    def call(self, method, params=None, session=None):
        if method == "Target.getTargets":
            return {"targetInfos": [{"targetId": "gone", "type": "page"}, {"targetId": "t2", "type": "page"}]}
        if method == "Target.attachToTarget":
            if params["targetId"] == "gone":
                raise cdp_mod.CdpCallError(method, "No target with given id found")
            return {"sessionId": "s2"}
        if method == "Page.getFrameTree":
            return {"frameTree": tree("M", "https://a.tld")}
        return {}

    def attach(self, target_id):
        return self.call("Target.attachToTarget", {"targetId": target_id})["sessionId"]

    def take_events(self, method, session):
        return []


def test_a_tab_that_vanishes_is_skipped_unless_it_was_asked_for():
    assert [p.session for p in browser._pages(Tabs(), None)] == ["s2"]
    with pytest.raises(browser.FieldNotFound):
        browser._pages(Tabs(), "gone")


def test_fill_of_a_locked_system_item_is_locked_not_unbound():
    backend = LockedHidesItems()
    backend.add_system("login/12", SECRET.encode(), "github", {"url": "https://github.com/login"})
    backend.locked = True
    kc = Keychain(USER, backend=backend, policy=Policy(), audit=Audit(enabled=False))
    with pytest.raises(Locked):  # exit 9, not exit 8 "not bound to a website"
        kc.fill("system:login/12", FakePage("https://github.com/login"), "#pw")


def test_target_needs_a_devtools_url():
    with pytest.raises(UsageError, match="--target"):
        keychain("ba").fill(REF, FakePage(), "#pw", target="T1")


def test_capturing_an_empty_field_is_a_field_problem():
    with pytest.raises(browser.FieldNotFound, match="empty"):
        keychain("ba").capture(REF, FakePage(describe={"type": "text"}), "#token")


class ScriptedSocket:
    """Stands in for the WebSocket under Cdp: answers every call, records what was sent."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send_text(self, text: str) -> None:
        self.sent.append(json.loads(text))

    def recv_text(self) -> str:
        msg = self.sent[-1]
        attach = msg["method"] == "Target.attachToTarget"
        result = {"sessionId": f"s-{msg['params']['targetId']}"} if attach else {}
        return json.dumps({"id": msg["id"], "result": result})


def test_a_borrowed_connection_gets_its_sessions_detached():
    ws = ScriptedSocket()
    conn = cdp_mod.Cdp(ws)
    assert conn.attach("T1") == "s-T1" and conn.attach("T2") == "s-T2"
    conn.detach_attached()
    detached = [m["params"]["sessionId"] for m in ws.sent if m["method"] == "Target.detachFromTarget"]
    assert sorted(detached) == ["s-T1", "s-T2"] and conn.attached == []


def test_sessions_the_caller_opened_before_the_fill_stay_open():
    ws = ScriptedSocket()
    conn = cdp_mod.Cdp(ws)
    conn.attach("MINE")
    before = len(conn.attached)
    conn.attach("T1")
    conn.detach_attached(before)
    detached = [m["params"]["sessionId"] for m in ws.sent if m["method"] == "Target.detachFromTarget"]
    assert detached == ["s-T1"] and conn.attached == ["s-MINE"]


def test_a_dead_browser_socket_is_unavailable_not_a_raw_oserror():
    class Broken:
        def sendall(self, data):
            raise BrokenPipeError

        def close(self):
            pass

    ws = object.__new__(cdp_mod.WebSocket)
    ws.sock = Broken()
    with pytest.raises(BackendUnavailable, match="connection failed"):
        ws.send_text("{}")
    ws.close()  # closing a dead connection stays quiet


def test_the_adapters_own_message_is_not_kept_as_the_cause():
    def boom(method, params):
        raise RuntimeError("quoted request with the value")

    with pytest.raises(cdp_mod.CdpCallError) as exc:
        cdp_mod.SessionCdp(boom).call("Runtime.callFunctionOn", {})
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_a_field_that_changed_during_the_wait_gets_nothing_written():
    page = FakePage()
    page.write_allowed = False
    with pytest.raises(PolicyDenied, match="changed while waiting"):
        keychain("ba").fill(REF, page, "#pw")
    assert page.value is None


def test_two_matches_in_one_frame_are_ambiguous():
    class TwoPasswordFields(FakePage):
        def send(self, method, params=None):
            if method == "Runtime.evaluate":
                assert browser._AMBIGUOUS in params["expression"]
                return {"exceptionDetails": {"exception": {"description": f"Error: {browser._AMBIGUOUS}"}}}
            return super().send(method, params)

    page = TwoPasswordFields()
    with pytest.raises(browser.FieldNotFound, match="several fields in one frame"):
        keychain("ba").fill(REF, page, "input[type=password]")
    assert page.value is None


def test_a_credential_replaced_while_it_is_fetched_is_not_typed():
    class ReplacedMeanwhile(LockedHidesItems):
        def get(self, ref):
            value = super().get(ref)
            self.set(ref, b"someone-elses", None, None, origin="https://other.tld")
            return value

    backend = ReplacedMeanwhile()
    backend.set(parse_item_ref(REF), SECRET.encode(), None, None, origin="https://site.tld")
    policy = Policy.from_dict({"callers": {"ba": {"fill": ["https://site.tld"], "approve": False}}})
    kc = Keychain("ba", backend=backend, policy=policy, audit=Audit(enabled=False))
    page = FakePage()
    with pytest.raises(PolicyDenied, match="was changed while it was being filled"):
        kc.fill(REF, page, "#pw")
    assert page.value is None


def test_capture_on_a_subdomain_keeps_the_existing_binding():
    kc = keychain("ba")
    page = FakePage("https://app.site.tld/settings", describe={"type": "text"})
    page.value = "captured-token"
    assert kc.capture(REF, page, "#token")["origin"] == "https://site.tld"
    assert kc.backend.info(parse_item_ref(REF)).origin == "https://site.tld"


def test_capture_refuses_a_field_that_is_not_a_credential_by_size():
    kc = keychain("ba")
    page = FakePage(describe={"type": "text"})
    page.value = "x" * (browser.MAX_CAPTURE + 1)
    with pytest.raises(UsageError, match="not a credential"):
        kc.capture(REF, page, "#token")
    assert kc.backend.get(parse_item_ref(REF)) == SECRET.encode()
