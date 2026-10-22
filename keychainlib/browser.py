"""`keychain fill` / `keychain capture`: move a credential between the store and a browser field
over the Chrome DevTools Protocol, inside this process.

fill: store → the ``value`` of one checked element: a visible ``<input type=password>`` (or a
username field) whose frame, and every frame above it, passes the origin rules in
`keychainlib.origins` immediately before the value is written. capture: a field's value →
store, recording the field's origin. The value never reaches argv, stdout, a log or the audit
journal.

The value is written to the checked element itself (``Runtime.callFunctionOn`` on its object
id), not typed with ``Input.insertText``: typed text goes to whatever has focus when it
arrives, and a cross-origin iframe on the page could take focus between our check and the
keystrokes. ``input`` and ``change`` events follow, so page frameworks see the new value.

Page scripts cannot lie to these checks: element lookups run in an isolated world (the page's
own prototypes and globals are not visible there), and frame URLs come from the browser's
frame tree, not from ``document.URL``. Cross-site iframes run in their own renderer process
(site isolation); they are reached through auto-attached child sessions.

After a password is written, the field must still be ``type=password`` and masked (CSS
``-webkit-text-security`` not ``none``): a page that unmasks it would put the value on
screenshots, so the field is cleared and the fill refused.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass

from .cdp import Cdp, CdpCallError, SessionCdp
from .errors import BackendError, PolicyDenied, UsageError
from .origins import Origin, binds, check_scheme, fill_test_mode, parse_origin

WORLD = "keychain-cli"
PASSWORD, USERNAME, CAPTURE = "password", "username", "capture"
FIELDS = (PASSWORD, USERNAME)
_MAX_FRAME_DEPTH = 16
_SECURITY_EVENT = "Security.visibleSecurityStateChanged"
_AMBIGUOUS = "keychain-ambiguous-selector"  # thrown in the page when a selector matches twice
MAX_CAPTURE = 64 * 1024  # the same cap `keychain set` puts on a value read from stdin

_DESCRIBE = """function () {
  const e = this, style = e.ownerDocument.defaultView.getComputedStyle(e);
  return {tag: e.tagName, type: (e.type || '').toLowerCase(), disabled: !!e.disabled,
          readOnly: !!e.readOnly, connected: e.isConnected, visibility: style.visibility,
          masking: style.webkitTextSecurity || '',
          autocomplete: (e.getAttribute('autocomplete') || '').toLowerCase()};
}"""
_FOCUS = """function () {
  this.focus();
  return this.ownerDocument.activeElement === this;
}"""
# Runs in the isolated world, so `value` is the native setter whatever the page redefined. The
# element is re-checked in the same call that writes (a page may change it while a human
# approves): disabled, read-only, or (a password) no longer masked: nothing is written.
_WRITE = """function (value, password) {
  const style = this.ownerDocument.defaultView.getComputedStyle(this);
  if (this.disabled || this.readOnly || (password &&
      ((this.type || '').toLowerCase() !== 'password' || style.webkitTextSecurity === 'none'))) {
    return false;
  }
  this.value = value;
  this.dispatchEvent(new InputEvent('input', {bubbles: true, composed: true,
                                              inputType: 'insertReplacementText'}));
  this.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}"""
_AFTER = """function (n) {
  const style = this.ownerDocument.defaultView.getComputedStyle(this);
  return {type: (this.type || '').toLowerCase(), complete: this.value.length === n,
          connected: this.isConnected, masking: style.webkitTextSecurity || ''};
}"""
_CLEAR = """function () {
  this.value = '';
  this.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'deleteContent'}));
}"""
_VALUE = "function () { return this.value; }"
_TAG = "function () { return this.tagName; }"


class FieldNotFound(UsageError):
    """No element (or more than one) matches: exit 2, like a bad selector."""


@dataclass
class Frame:
    id: str
    url: str
    parent: str | None
    session: str | None


class PageTarget:
    """One tab: its session plus sessions of its out-of-process (cross-site) iframes."""

    def __init__(self, cdp: Cdp | SessionCdp, session: str | None) -> None:
        self.cdp = cdp
        self.session = session
        self.children: list[str] = []
        self._tls: bool | None = None
        if cdp.supports_sessions:
            self._attach_children(session, 0)
        self.main_frame = self.cdp.call("Page.getFrameTree", session=session)["frameTree"]["frame"]["id"]

    def _attach_children(self, session: str | None, depth: int) -> None:
        if depth > _MAX_FRAME_DEPTH:
            return
        params = {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True}
        # Chromium sends attachedToTarget for the iframes that already exist before it answers
        # setAutoAttach, so they are all queued by now. One it missed has no session here: its
        # fields are not found and its frames break chain(), which refuses; never a silent pass.
        self.cdp.call("Target.setAutoAttach", params, session=session)
        for event, _parent in self.cdp.take_events("Target.attachedToTarget", session):
            if event["targetInfo"]["type"] == "iframe":
                self.children.append(event["sessionId"])
                self._attach_children(event["sessionId"], depth + 1)

    def frames(self) -> dict[str, Frame]:
        """Every frame of the tab, with the session that owns it (fresh from the browser)."""
        out: dict[str, Frame] = {}

        def walk(node: dict, session: str | None) -> None:
            f = node["frame"]
            # A child session's root is an iframe whose parentId points into the parent session.
            parent = f.get("parentId") or (out[f["id"]].parent if f["id"] in out else None)
            out[f["id"]] = Frame(f["id"], f.get("url", ""), parent, session)
            for child in node.get("childFrames", []):
                walk(child, session)

        for session in [self.session, *self.children]:
            try:
                tree = self.cdp.call("Page.getFrameTree", session=session)["frameTree"]
            except CdpCallError:
                continue  # an iframe that detached meanwhile; chain() refuses gaps it leaves
            walk(tree, session)
        return out

    def chain(self, frame_id: str) -> list[Frame]:
        """The frame and every ancestor up to the tab's main frame. A gap (an ancestor whose
        session could not be read) or a chain deeper than the limit is refused, never skipped."""
        frames = self.frames()
        out: list[Frame] = []
        current: str | None = frame_id
        while current is not None:
            if current not in frames or len(out) >= _MAX_FRAME_DEPTH:
                raise PolicyDenied(
                    "cannot resolve every frame around the field",
                    why="a frame is gone (the page navigated) or the frames nest too deep",
                )
            out.append(frames[current])
            current = frames[current].parent
        if out[-1].id != self.main_frame:
            raise PolicyDenied("the field's frames do not lead to the tab's top frame")
        return out

    def world(self, frame: Frame) -> int:
        return self.cdp.call(
            "Page.createIsolatedWorld", {"frameId": frame.id, "worldName": WORLD}, session=frame.session
        )["executionContextId"]

    def node(self, frame: Frame, context: int, expression: str, what: str) -> str | None:
        """objectId of the element ``expression`` returns in the isolated world, or None."""
        r = self.cdp.call(
            "Runtime.evaluate", {"expression": expression, "contextId": context}, session=frame.session
        )
        if r.get("exceptionDetails"):
            if _AMBIGUOUS in json.dumps(r["exceptionDetails"]):
                raise FieldNotFound(
                    f"{what} matches several fields in one frame", fix="make the selector specific"
                )
            raise UsageError(f"{what} failed in the page", fix="check the CSS selector")
        obj = r.get("result", {})
        return obj.get("objectId") if obj.get("subtype") == "node" else None

    def secure_transport(self) -> bool | None:
        """The tab's TLS verdict, asked once: True for a verified (or plain-http) page, False
        when the certificate is invalid (a bypassed interstitial, a browser started with
        --ignore-certificate-errors), None when the browser does not tell us."""
        if self._tls is None:
            self._tls = self._ask_tls()
        return self._tls

    def _ask_tls(self) -> bool | None:
        if not self.cdp.watch(_SECURITY_EVENT):
            return None
        self.cdp.call("Security.enable", session=self.session)
        try:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                events = self.cdp.take_events(_SECURITY_EVENT, self.session)
                states = [e["visibleSecurityState"] for e, _s in events]
                if states:
                    state = states[-1]
                    cert = state.get("certificateSecurityState") or {}
                    return not (
                        state.get("securityState") in ("insecure", "insecure-broken")
                        or cert.get("certificateNetworkError")
                    )
                time.sleep(0.05)
                self.cdp.call("Page.getFrameTree", session=self.session)  # let events arrive
            return None
        finally:
            self.cdp.call("Security.disable", session=self.session)


@dataclass
class Field:
    page: PageTarget
    frame: Frame
    object_id: str

    def call(self, function: str, *args) -> object:
        r = self.page.cdp.call(
            "Runtime.callFunctionOn",
            {
                "functionDeclaration": function,
                "objectId": self.object_id,
                "arguments": [{"value": a} for a in args],
                "returnByValue": True,
            },
            session=self.frame.session,
        )
        if r.get("exceptionDetails"):
            raise BackendError("a script on the field failed", why="exception in the isolated world")
        return r.get("result", {}).get("value")


def _pages(cdp: Cdp | SessionCdp, target: str | None) -> list[PageTarget]:
    if not cdp.supports_sessions:
        if target:
            raise UsageError("--target needs a DevTools URL: a CDP session object is bound to one tab")
        return [PageTarget(cdp, None)]
    infos = [t for t in cdp.call("Target.getTargets")["targetInfos"] if t["type"] == "page"]
    if target:
        infos = [t for t in infos if t["targetId"] == target]
        if not infos:
            raise FieldNotFound(f"no browser tab with target id {target}")
    pages = []
    for info in infos:
        try:
            pages.append(PageTarget(cdp, cdp.attach(info["targetId"])))
        except CdpCallError as exc:
            if target:
                raise FieldNotFound(f"cannot attach to the browser tab {target}", why=exc.message) from exc
            # Another tab closed (an OAuth popup) or refused us: it holds no field we can use.
    return pages


def _by_selector(page: PageTarget, selector: str) -> list[Field]:
    found = []
    # querySelector alone would hide a second match in the same frame: refuse the ambiguity.
    expression = (
        f"(() => {{ const m = document.querySelectorAll({json.dumps(selector)}); "
        f"if (m.length > 1) throw new Error({json.dumps(_AMBIGUOUS)}); return m[0] || null; }})()"
    )
    for frame in page.frames().values():
        try:
            obj = page.node(frame, page.world(frame), expression, "the CSS selector")
        except CdpCallError:
            continue  # the frame detached while we looked
        if obj:
            found.append(Field(page, frame, obj))
    return found


def _focused(page: PageTarget) -> Field | None:
    frames = page.frames()
    frame = frames.get(page.main_frame)
    if frame is None:  # the tab navigated or closed meanwhile
        return None
    for _ in range(_MAX_FRAME_DEPTH):
        try:
            obj = page.node(frame, page.world(frame), "document.activeElement", "finding the focused element")
            if not obj:
                return None
            tag = Field(page, frame, obj).call(_TAG)
            if tag in ("IFRAME", "FRAME"):
                node = page.cdp.call("DOM.describeNode", {"objectId": obj}, session=frame.session)["node"]
                frames = page.frames()
                if node.get("frameId") not in frames:
                    return None
                frame = frames[node["frameId"]]
                continue
        except CdpCallError:
            # The frame detached, or it is a cross-site iframe this connection cannot reach (a
            # session object is bound to one renderer): no field found there.
            return None
        return None if tag in ("BODY", "HTML", None) else Field(page, frame, obj)
    return None


def locate(cdp: Cdp | SessionCdp, selector: str | None, target: str | None) -> Field:
    """The one field ``selector`` matches (or the focused element when it is None)."""
    found: list[Field] = []
    for page in _pages(cdp, target):
        if selector is None:
            field = _focused(page)
            found += [field] if field else []
        else:
            found += _by_selector(page, selector)
    what = "the selector" if selector is not None else "the focused element"
    if not found:
        raise FieldNotFound(
            f"no element matches {what}" if selector is not None else "no field has focus",
            fix="check the selector / focus the field, and pass --target TAB_ID for a specific tab",
        )
    if len(found) > 1:
        raise FieldNotFound(
            f"{what} matches fields in {len(found)} frames or tabs",
            fix="make the selector specific, or pass --target TAB_ID",
        )
    return found[0]


def check_field(field: Field, kind: str) -> None:
    """The element must be a usable field of ``kind`` (PASSWORD, USERNAME or CAPTURE)."""
    d = field.call(_DESCRIBE)
    if not isinstance(d, dict) or not d.get("connected"):
        raise FieldNotFound("the field is no longer in the page")
    if kind == CAPTURE:
        if d["tag"] not in ("INPUT", "TEXTAREA"):
            raise PolicyDenied("capture reads only <input> and <textarea> fields")
        return
    if d["tag"] != "INPUT":
        raise PolicyDenied(f"refusing to fill a <{str(d['tag']).lower()}>: not an input field")
    if kind == PASSWORD:
        if d["type"] != "password":
            raise PolicyDenied(
                f"refusing to fill a password into an input of type {d['type']!r}",
                why="only type=password fields hide the value on screen and in screenshots",
            )
        if d["masking"] == "none":
            raise PolicyDenied("refusing to fill a password field the page shows unmasked")
    elif kind == USERNAME:
        named = bool(set(d["autocomplete"].split()) & {"username", "email"})
        if not (d["type"] == "email" or (d["type"] == "text" and named)):
            raise PolicyDenied(
                "refusing to fill a username: the field is neither type=email nor type=text with "
                "autocomplete=username|email",
            )
    else:
        raise UsageError(f"unknown field kind {kind!r}")
    if d["disabled"] or d["readOnly"]:
        raise PolicyDenied("the field is disabled or read-only")
    if d["visibility"] in ("hidden", "collapse"):
        raise PolicyDenied("the field is not visible")
    try:
        box = field.page.cdp.call(
            "DOM.getBoxModel", {"objectId": field.object_id}, session=field.frame.session
        )
    except CdpCallError as exc:
        raise PolicyDenied("the field is not visible (no layout box)") from exc
    model = box.get("model", {})
    if not (model.get("width", 0) > 0 and model.get("height", 0) > 0):
        raise PolicyDenied("the field is not visible (zero size)")


def frame_origins(
    field: Field,
    narrow: Origin | None,
    allow: Callable[[str], None] | None = None,
    record: Origin | None = None,
    subdomains: bool = True,
) -> list[Origin]:
    """Check the field's frame and every frame above it; return their origins, field first.
    ``allow`` raises when the caller's policy does not cover an origin; ``record`` is the
    credential's origin (``subdomains=False`` demands its exact host); ``narrow`` is --origin."""
    origins = []
    for frame in field.page.chain(field.frame.id):
        origin = check_scheme(parse_origin(frame.url), frame.url)
        if narrow is not None and origin != narrow:
            raise PolicyDenied(
                f"the field's page is {origin}, not {narrow}",
                why="--origin was given; the frame (or a frame around it) has another origin",
            )
        if allow is not None:
            allow(str(origin))
        if record is not None and not binds(record, origin, subdomains=subdomains):
            raise PolicyDenied(
                f"this credential belongs to {record}; the page (or a frame around the field) is {origin}",
                why="a credential is only typed into its own site (phishing protection)",
            )
        origins.append(origin)
    top = origins[-1]
    # Self-signed certificates are tolerated only for a loopback test page (KEYCHAIN_FILL_TEST=1).
    if not (top.loopback and fill_test_mode()):
        verdict = field.page.secure_transport()
        if verdict is not True:
            raise PolicyDenied(
                f"the TLS certificate of {top} is not valid"
                if verdict is False
                else f"cannot verify the TLS state of {top} through this CDP connection",
                why="a credential must not go to a page whose server identity is unverified",
            )
    return origins


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def write(field: Field, value: str, kind: str) -> None:
    """Focus the field and set ``value`` on it; verify the result without reading the value."""
    if field.page.cdp.supports_sessions:
        # Headless and background tabs: let focus() stick. The override belongs to our own
        # session and ends when that session detaches (on close, or Cdp.detach_attached() for
        # a borrowed connection), so other clients' sessions (Playwright's) are left as they were.
        field.page.cdp.call(
            "Emulation.setFocusEmulationEnabled", {"enabled": True}, session=field.page.session
        )
    if not field.call(_FOCUS):
        raise PolicyDenied("the field does not accept focus")
    if field.call(_WRITE, value, kind == PASSWORD) is not True:
        raise PolicyDenied(
            "the field changed while waiting (disabled, read-only or no longer a masked password); "
            "nothing was written"
        )
    after = field.call(_AFTER, utf16_len(value))
    if not isinstance(after, dict) or not after.get("connected"):
        raise BackendError("the field left the page while it was filled")
    if kind == PASSWORD and (after["type"] != "password" or after["masking"] == "none"):
        field.call(_CLEAR)
        raise PolicyDenied(
            "the page unmasked the password field while it was filled; it was cleared",
            why="a visible password would show up on screenshots",
        )
    if not after["complete"]:
        field.call(_CLEAR)
        raise BackendError(
            "the field did not take the whole value (maxlength, or a script rewrote it); it was cleared"
        )


def read_value(field: Field) -> str:
    value = field.call(_VALUE)
    if not isinstance(value, str) or not value:
        raise FieldNotFound("the field is empty: nothing to capture")
    if len(value.encode("utf-8")) > MAX_CAPTURE:
        raise UsageError(f"the field holds more than {MAX_CAPTURE} bytes: not a credential")
    return value
