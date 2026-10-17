"""The library API: one object that applies policy and audit around a backend.

    from keychainlib import Keychain
    kc = Keychain(caller="tg-cli")
    token = kc.get("tg-cli/bot-token")     # a Secret: prints as Secret(***)
    requests.post(url, headers={"Authorization": f"Bearer {token.reveal()}"})

Every call is checked against the policy and journaled (without the value) before the backend
is touched; a denied call never reaches the store.
"""

from __future__ import annotations

from .audit import Audit
from .backends import Backend, ItemInfo, SystemItem, default_backend
from .context import in_agent_context, resolve_caller
from .errors import KeychainError, NotFound, PolicyDenied, UsageError
from .policy import READ, WRITE, Policy
from .refs import Ref, SystemRef, parse_item_ref, parse_ref
from .secret import Secret


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
    ) -> None:
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
        self._guarded("set", r, WRITE, lambda: self.backend.set(r, raw, label, note))

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
