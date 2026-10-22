"""The library API: one object that applies policy and audit around a backend.

    from keychainlib import Keychain
    kc = Keychain(caller="tg-cli")
    token = kc.get("tg-cli/bot-token")     # a Secret: prints as Secret(***)
    requests.post(url, headers={"Authorization": f"Bearer {token.reveal()}"})

Every call is checked against the policy and journaled (without the value) before the backend
is touched; a denied call never reaches the store.
"""

from __future__ import annotations

import contextlib

from . import approval
from .audit import Audit
from .backends import Backend, ItemInfo, SystemItem, default_backend
from .context import USER, in_agent_context, resolve_caller
from .errors import KeychainError, NotFound, PolicyDenied, UsageError
from .origins import Origin, binds, normalize_origin, parse_origin
from .policy import READ, WRITE, Policy
from .refs import Ref, SystemRef, parse_item_ref, parse_ref
from .secret import Secret

# System-item attributes that name the website a password belongs to, in order of preference.
_SYSTEM_URL_ATTRIBUTES = ("url", "URL", "origin_url", "signon_realm", "uri")  # URL: KeePassXC
# macOS internet passwords name it by protocol code, server and port instead.
_MACOS_PROTOCOLS = {"htps": "https", "http": "http"}


def _system_urls(attrs: dict[str, str]) -> list[str]:
    """Every URL a system item names, best first; the first one that parses is used."""
    urls = [attrs[k] for k in _SYSTEM_URL_ATTRIBUTES if attrs.get(k)]
    scheme = _MACOS_PROTOCOLS.get(attrs.get("ptcl", ""))
    if scheme and attrs.get("srvr"):
        port = attrs.get("port", "0")
        urls.append(f"{scheme}://{attrs['srvr']}" + (f":{port}" if port not in ("", "0") else ""))
    return urls


def _outcome(exc: BaseException) -> str:
    return type(exc).__name__ if isinstance(exc, KeychainError) else "error"


class Keychain:
    def __init__(
        self,
        caller: str | None = None,
        *,
        backend: Backend | None = None,
        policy: Policy | None = None,
        audit: Audit | None = None,
        store: str | None = None,
        interactive: bool = True,
    ) -> None:
        self.agent = in_agent_context()
        self.caller = resolve_caller(caller)
        self._backend = backend
        self._store = store
        self._interactive = interactive
        self.policy = policy if policy is not None else Policy.load()
        self.audit = audit if audit is not None else Audit()

    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = default_backend(self._store, self._interactive)
        return self._backend

    def _backend_name(self) -> str:
        return self._backend.name if self._backend is not None else ""

    def _guarded(self, op: str, ref: Ref | SystemRef, access: str, fn, extra: dict | None = None):
        try:
            self.policy.check(self.caller, access, ref)
            result = fn()
        except BaseException as exc:
            self.audit.record(
                op,
                str(ref),
                self.caller,
                _outcome(exc),
                agent=self.agent,
                backend=self._backend_name(),
                extra=extra,
            )
            raise
        self.audit.record(
            op, str(ref), self.caller, "ok", agent=self.agent, backend=self._backend_name(), extra=extra
        )
        return result

    def get(self, ref: str | Ref | SystemRef, *, purpose: str = "get") -> Secret:
        r = parse_ref(ref) if isinstance(ref, str) else ref
        if isinstance(r, SystemRef):
            return self._guarded(purpose, r, READ, lambda: Secret(self.backend.system_get(r.id)))
        return self._guarded(purpose, r, READ, lambda: Secret(self.backend.get(r)))

    def set(
        self,
        ref: str | Ref,
        value: str | bytes | Secret,
        *,
        label: str | None = None,
        note: str | None = None,
        origin: str | None = None,
    ) -> None:
        """Store ``value``. ``origin`` binds the credential to a website for `fill`
        (``""`` removes the binding, ``None`` keeps the current one)."""
        r = parse_item_ref(ref) if isinstance(ref, str) else ref
        raw = (
            value.reveal_bytes()
            if isinstance(value, Secret)
            else (value.encode("utf-8") if isinstance(value, str) else bytes(value))
        )
        if not raw:
            raise UsageError(f"refusing to store an empty secret for {r}")
        for text, name in ((label, "label"), (note, "note")):
            if text is not None and ("\n" in text or len(text) > 256):
                raise UsageError(f"{name} must be one line of at most 256 characters")
        origin = normalize_origin(origin) if origin else origin
        self._guarded("set", r, WRITE, lambda: self.backend.set(r, raw, label, note, origin))

    def delete(self, ref: str | Ref) -> None:
        r = parse_item_ref(ref) if isinstance(ref, str) else ref
        self._guarded("delete", r, WRITE, lambda: self.backend.delete(r))

    def info(self, ref: str | Ref) -> ItemInfo:
        r = parse_item_ref(ref) if isinstance(ref, str) else ref
        return self._guarded("info", r, READ, lambda: self.backend.info(r))

    def exists(self, ref: str | Ref) -> bool:
        try:
            self.info(ref)
        except NotFound:
            return False
        return True

    def list(self, service: str | None = None) -> list[ItemInfo]:
        """Metadata of the items this caller may read (all of them for `user`)."""
        items = self.backend.list(service)
        visible = [i for i in items if self.policy.allows(self.caller, READ, i.ref)]
        self.audit.record(
            "list",
            f"{service or '*'}/*",
            self.caller,
            "ok",
            agent=self.agent,
            backend=self.backend.name,
            extra={"count": len(visible)},
        )
        return visible

    def system_list(self, query: dict[str, str] | None = None) -> list[SystemItem]:
        items = self.backend.system_list(dict(query or {}))
        visible = [i for i in items if self.policy.allows(self.caller, READ, SystemRef(i.id))]
        self.audit.record(
            "system-list",
            "system:*",
            self.caller,
            "ok",
            agent=self.agent,
            backend=self.backend.name,
            extra={"count": len(visible)},
        )
        return visible

    # ── browser ──────────────────────────────────────────────────────────────

    def _record_origin(self, ref: Ref | SystemRef) -> Origin:
        """The website a credential belongs to: our `origin` attribute, a system item's URL."""
        if isinstance(ref, SystemRef):
            self.backend.ensure_unlocked(f"filling {ref}", system_id=ref.id)
            candidates = _system_urls(self.backend.system_info(ref.id).attributes)
            fix = "the system item has no url attribute; store the login: keychain set REF --origin URL"
        else:
            self.backend.ensure_unlocked(f"filling {ref}")
            candidates = [self.backend.info(ref).origin or ""]
            fix = f"ask the user to bind it: keychain set {ref} --origin https://site.tld"
        origin = next((o for o in map(parse_origin, candidates) if o is not None), None)
        if origin is None:
            raise PolicyDenied(
                f"{ref} is not bound to a website, so it cannot be filled into one",
                why="fill types a credential only into the site it belongs to",
                fix=fix,
            )
        return origin

    def _journal(self, op: str, ref: Ref | SystemRef, fn, extra: dict):
        """Run ``fn`` and journal the outcome; ``extra`` may be filled in by ``fn``."""
        try:
            result = fn()
        except BaseException as exc:
            self.audit.record(
                op,
                str(ref),
                self.caller,
                _outcome(exc),
                agent=self.agent,
                backend=self._backend_name(),
                extra=extra,
            )
            raise
        self.audit.record(
            op, str(ref), self.caller, "ok", agent=self.agent, backend=self._backend_name(), extra=extra
        )
        return result

    def _approve_fill(self, ref: Ref | SystemRef, page: Origin, field: str, extra: dict) -> None:
        """Ask the human before the value is fetched, once the page and credential are known to
        belong together (so nobody is asked about a fill that would be refused anyway)."""
        if not self.policy.needs_approval(self.caller):
            extra["approval"] = "not required"
            return
        command, source = approval.resolve_command(self.policy.approval_cmd, agent=self.agent)
        extra["approval"] = f"asked via {source}"
        approval.require(
            command=command,
            timeout=self.policy.approval_timeout,
            caller=self.caller,
            ref=str(ref),
            origin=str(page),
            field=field,
        )
        extra["approval"] = "approved"

    def fill(
        self,
        ref: str | Ref | SystemRef,
        cdp,
        selector: str | None = None,
        *,
        field: str = "password",
        origin: str | None = None,
        target: str | None = None,
    ) -> dict:
        """Write the credential ``ref`` into a browser field without the value leaving this
        process. ``cdp`` is a DevTools URL (``http://127.0.0.1:PORT``, ``ws://…``) or a
        session object with ``send(method, params)`` and ``on(event, handler)``, such as
        Playwright's sync ``page.context.new_cdp_session(page)``. ``selector`` None means the
        focused element. Returns ``{"filled": True, "selector": …, "origin": …}``."""
        from . import browser

        r = parse_ref(ref) if isinstance(ref, str) else ref
        if field not in browser.FIELDS:
            raise UsageError(f"--field must be one of {', '.join(browser.FIELDS)}")
        narrow = _narrow(origin)
        # A caller with no grant (`user`) gets the credential's exact host only; others reach
        # a subdomain only through a fill grant that names it.
        subdomains = self.caller != USER
        extra: dict = {"selector": selector, "field": field}

        def allow(page_origin: str) -> None:
            self.policy.check_fill(self.caller, page_origin)

        def run() -> dict:
            # Whoever drives the browser can read a filled field back, so filling is a way of
            # reading: the caller needs the read right on the ref as well as the fill grant.
            self.policy.check(self.caller, READ, r)
            with _connected(cdp) as conn:
                target_field = browser.locate(conn, selector, target)
                # Policy and the page are settled before the store is touched (or unlocked).
                extra["origin"] = str(browser.frame_origins(target_field, narrow, allow)[0])
                browser.check_field(target_field, field)
                record = self._record_origin(r)
                # The phishing check: every frame must belong to the credential's own site.
                checked = browser.frame_origins(target_field, narrow, allow, record, subdomains)[0]
                self._approve_fill(r, checked, field, extra)
                secret = Secret(
                    self.backend.system_get(r.id) if isinstance(r, SystemRef) else self.backend.get(r)
                )
                try:
                    text = secret.reveal()
                except UnicodeDecodeError:
                    raise UsageError(f"{r} is not text, so it cannot be typed into a field") from None
                if "\n" in text or "\r" in text:
                    # An <input> drops line breaks: the field would hold a different value.
                    raise UsageError(
                        f"{r} contains a line break, which a single-line field cannot hold",
                        fix="store it again without the line break",
                    )
                # The credential may have been replaced (value and site together) while the human
                # decided or the store answered: then the value in hand is not the one checked.
                if self._record_origin(r) != record:
                    raise PolicyDenied(
                        f"{r} was changed while it was being filled; nothing was typed",
                        fix="retry the fill",
                    )
                # Again right before writing: the page may have navigated or the field changed
                # (the write re-checks it inside the browser as well).
                browser.check_field(target_field, field)
                page = browser.frame_origins(target_field, narrow, allow, record, subdomains)[0]
                extra["origin"] = str(page)
                browser.write(target_field, text, field)
                return {"filled": True, "selector": selector, "origin": str(page)}

        return self._journal("fill", r, run, extra)

    def _stored_origin(self, ref: Ref) -> Origin | None:
        """The website an existing item is bound to; None for a missing or unbound item."""
        try:
            return parse_origin(self.backend.info(ref).origin or "")
        except NotFound:
            return None

    def capture(
        self,
        ref: str | Ref,
        cdp,
        selector: str | None = None,
        *,
        label: str | None = None,
        origin: str | None = None,
        target: str | None = None,
    ) -> dict:
        """Store the value of a browser field as ``ref``, bound to the field's origin. The value
        goes from the page into the store without being printed."""
        from . import browser

        r = parse_item_ref(ref) if isinstance(ref, str) else ref
        narrow = _narrow(origin)
        if label is not None and ("\n" in label or len(label) > 256):
            raise UsageError("label must be one line of at most 256 characters")
        extra: dict = {"selector": selector}

        def run() -> dict:
            self.policy.check(self.caller, WRITE, r)
            with _connected(cdp) as conn:
                source = browser.locate(conn, selector, target)
                browser.check_field(source, browser.CAPTURE)
                page = browser.frame_origins(source, narrow)[0]
                extra["origin"] = str(page)
                self.backend.ensure_unlocked(f"capturing into {r}")  # else a lookup may miss it
                current = self._stored_origin(r)
                if current is not None and not binds(current, page):
                    raise PolicyDenied(
                        f"{r} belongs to {current}; refusing to overwrite it from {page}",
                        fix="capture into another ref, or delete the old one first",
                    )
                value = browser.read_value(source)
            # An existing binding to the page's own site (or its parent) is kept: capturing on a
            # subdomain must not narrow where the credential may later be filled.
            bound = current if current is not None else page
            if self._stored_origin(r) != current:
                raise PolicyDenied(f"{r} was changed while it was being captured; nothing was stored")
            self.backend.set(r, value.encode("utf-8"), label, note=None, origin=str(bound))
            return {"captured": True, "ref": str(r), "origin": str(bound)}

        return self._journal("capture", r, run, extra)

    def may_reveal(self) -> bool:
        return self.policy.may_reveal(self.caller, self.agent)

    def authorize(self, op: str, refs: list[Ref | SystemRef], access: str, *, reveal: bool = False) -> None:
        """Check every ref (and, with ``reveal``, the right to print values) before any of them
        touches the store. A refusal is journaled and raised; nothing is fetched or unlocked."""
        for ref in refs:
            try:
                self.policy.check(self.caller, access, ref)
                if reveal and not self.may_reveal():
                    raise PolicyDenied(
                        f"caller `{self.caller}` may not print {ref} inside an agent session",
                        why="a printed value lands in the agent's context window and transcript",
                        fix=f"inject it instead: keychain exec --env NAME={ref} -- command "
                        "(output is masked). Printing needs `reveal = true` for this "
                        "caller in the user's policy file, which only the human edits.",
                    )
            except PolicyDenied as exc:
                self.audit.record(
                    op, str(ref), self.caller, _outcome(exc), agent=self.agent, backend=self._backend_name()
                )
                raise


def _narrow(origin: str | None) -> Origin | None:
    """``--origin``: an exact origin the page must also have (it narrows, never widens)."""
    return parse_origin(normalize_origin(origin)) if origin is not None else None


@contextlib.contextmanager
def _connected(cdp):
    """A CDP connection: opened (and closed) here for a URL; for a connection or session the
    caller keeps using, what we added to it (sessions, event collection) is undone on exit."""
    from .cdp import Cdp, SessionCdp

    if isinstance(cdp, Cdp):
        before = len(cdp.attached)  # sessions the caller opened before us stay theirs
        try:
            yield cdp
        finally:
            cdp.detach_attached(before)
    elif isinstance(cdp, SessionCdp):
        yield cdp
    elif isinstance(cdp, str):
        conn = Cdp.connect(cdp)
        try:
            yield conn
        finally:
            conn.close()
    elif callable(getattr(cdp, "send", None)):
        adapter = SessionCdp(cdp.send, getattr(cdp, "on", None))
        try:
            yield adapter
        finally:
            adapter.close()
    else:
        raise UsageError("cdp must be a DevTools URL or a CDP session with send(method, params)")
