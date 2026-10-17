"""Linux backend: the freedesktop Secret Service (GNOME Keyring, KWallet 6, KeePassXC) over D-Bus.

Our items carry ``xdg:schema = ai.hyperide.keychain`` plus ``service`` / ``account`` (and an
optional ``note``) attributes, so `list` finds exactly the items keychain-cli manages and other
apps' items stay "system" items.

Transport security: the session is opened with the ``plain`` algorithm, so values cross the
user's session-bus socket unencrypted. That socket is reachable only by the same uid, which
can already ask the unlocked Secret Service for any value, so DH session encryption (which
also needs AES, absent from the stdlib) would not change who can read a secret.

Locked keyrings: an unlock needs either a GUI prompt (only when a display is available and
prompts are allowed) or `keychain unlock`, which asks for the keyring password on the TTY and
passes it to gnome-keyring's master-password interface. Headless sessions (SSH, cron,
systemd) therefore never hang on an invisible dialog: they fail fast with exit code 9.
"""

from __future__ import annotations

import contextlib
import getpass
import os
import re
import sys

from ..errors import (
    BackendError,
    BackendUnavailable,
    KeychainError,
    Locked,
    NotFound,
    PolicyDenied,
    UsageError,
)
from ..refs import Ref
from . import ItemInfo, SystemItem, safe_attributes
from .dbus import Connection, DBusConnectionError, DBusError, Variant

BUS = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
SERVICE = "org.freedesktop.Secret.Service"
COLLECTION = "org.freedesktop.Secret.Collection"
ITEM = "org.freedesktop.Secret.Item"
PROMPT = "org.freedesktop.Secret.Prompt"
PROPS = "org.freedesktop.DBus.Properties"
GNOME = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
COLLECTION_PREFIX = "/org/freedesktop/secrets/collection/"
SCHEMA = "ai.hyperide.keychain"
TEXT = "text/plain; charset=utf8"
NO_PROMPT = "/"
PROMPT_TIMEOUT = 300.0
_ID_RE = re.compile(r"[A-Za-z0-9_]+/[A-Za-z0-9_]+")

UNAVAILABLE_FIX = (
    "install and start a Secret Service: `sudo apt install gnome-keyring` (desktop sessions "
    "start it at login; headless: `keychain doctor` shows the exact steps)"
)


def _item_order(path: str) -> tuple[int, str]:
    """gnome-keyring numbers items in creation order (…/login/12); unknown shapes sort last."""
    tail = path.rsplit("/", 1)[-1]
    return (int(tail), path) if tail.isdigit() else (1 << 62, path)


def has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


class SecretServiceBackend:
    name = "secret-service"

    def __init__(
        self, collection: str | None = None, interactive: bool = True, address: str | None = None
    ) -> None:
        self.collection_name = collection
        self.interactive = interactive
        self.address = address
        self._conn: Connection | None = None
        self._session: str | None = None
        self._owner: str | None = None
        self._collection: str | None = None

    # ── plumbing ─────────────────────────────────────────────────────────────

    @property
    def conn(self) -> Connection:
        if self._conn is None:
            try:
                self._conn = Connection(self.address)
            except DBusConnectionError as exc:
                raise BackendUnavailable(
                    "cannot reach the D-Bus session bus",
                    why=str(exc),
                    fix="run inside a login session, or set "
                    "DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR; "
                    "see `keychain doctor`",
                ) from exc
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            self._session = None

    def _call(
        self,
        path: str,
        iface: str,
        member: str,
        sig: str = "",
        args: list | None = None,
        timeout: float | None = None,
        vanishable: bool = False,
    ) -> list:
        try:
            return self.conn.call(BUS, path, iface, member, sig, args, timeout=timeout)
        except DBusError as exc:
            if exc.name in (
                "org.freedesktop.DBus.Error.ServiceUnknown",
                "org.freedesktop.DBus.Error.NameHasNoOwner",
            ):
                raise BackendUnavailable(
                    "no Secret Service is running on the session bus", fix=UNAVAILABLE_FIX
                ) from exc
            if vanishable and exc.name in (
                "org.freedesktop.DBus.Error.UnknownObject",
                "org.freedesktop.DBus.Error.UnknownMethod",
            ):
                # Only for calls on an item path that a concurrent writer may have deleted:
                # gnome-keyring answers this way for a path that no longer exists.
                raise NotFound("the keyring item no longer exists", why=exc.name) from exc
            if exc.name == "org.freedesktop.Secret.Error.IsLocked":
                raise Locked("the keyring is locked", fix="keychain unlock") from exc
            if exc.name == "org.freedesktop.Secret.Error.NoSuchObject":
                raise NotFound("the keyring item or collection no longer exists") from exc
            if exc.name == "org.freedesktop.DBus.Error.AccessDenied":
                raise PolicyDenied("the Secret Service refused access", why=exc.message) from exc
            raise BackendError(f"Secret Service call {member} failed", why=exc.name) from exc
        except DBusConnectionError as exc:
            self.close()
            raise BackendUnavailable("the session bus connection failed", why=str(exc)) from exc

    def _prop(self, path: str, iface: str, name: str, vanishable: bool = False):
        return self._call(path, PROPS, "Get", "ss", [iface, name], vanishable=vanishable)[0]

    @property
    def session(self) -> str:
        if self._session is None:
            session = self._call(SERVICE_PATH, SERVICE, "OpenSession", "sv", ["plain", Variant("s", "")])[1]
            self._verify_owner()  # before the first value crosses the plain session
            self._session = session
        return self._session

    def _verify_owner(self) -> None:
        """The Secret Service must run as our uid: `plain` sends values to whoever owns the
        name, so a service started by another user must never receive one."""
        bus = ("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus")
        try:
            self._owner = self.conn.call(*bus, "GetNameOwner", "s", [BUS])[0]
            uid = self.conn.call(*bus, "GetConnectionUnixUser", "s", [BUS])[0]
        except DBusError as exc:
            raise BackendUnavailable("cannot identify the Secret Service owner", why=exc.name) from exc
        if uid != os.getuid():
            raise BackendUnavailable(
                f"the Secret Service on this bus runs as uid {uid}",
                why="values would be sent to another user's process",
                fix="check DBUS_SESSION_BUS_ADDRESS (`keychain doctor`)",
            )

    def _secret_struct(self, value: bytes) -> tuple:
        return (self.session, b"", bytes(value), TEXT)

    # ── collections and prompts ──────────────────────────────────────────────

    def _collections(self) -> list[str]:
        return list(self._prop(SERVICE_PATH, SERVICE, "Collections"))

    def collection(self) -> str:
        if self._collection is not None:
            return self._collection
        if self.collection_name:
            for path in self._collections():
                label = self._prop(path, COLLECTION, "Label")
                if self.collection_name in (label, path.rsplit("/", 1)[-1]):
                    self._collection = path
                    return path
            raise NotFound(
                f"no keyring collection named {self.collection_name!r}",
                fix="`keychain doctor` lists the collections",
            )
        path = self._call(SERVICE_PATH, SERVICE, "ReadAlias", "s", ["default"])[0]
        if path == NO_PROMPT:
            raise BackendUnavailable(
                "the Secret Service has no default keyring",
                why="a fresh or headless gnome-keyring has no 'login' keyring yet",
                fix="create one: `keychain unlock --create` (asks for a new keyring password)",
            )
        self._collection = path
        return path

    def _complete_prompt(self, prompt: str, what: str) -> None:
        if prompt == NO_PROMPT:
            return
        if not (self.interactive and has_display()):
            with contextlib.suppress(KeychainError):  # best effort; the useful error is below
                self._call(prompt, PROMPT, "Dismiss")
            raise Locked(
                f"{what} needs an unlock prompt, and no prompt can be shown here",
                why="no graphical session (headless SSH, cron or systemd) or "
                "prompts are disabled (--no-prompt)",
                fix="run `keychain unlock` in a terminal (asks for the keyring "
                "password on the TTY), then retry",
            )
        if self._owner is None:
            self._verify_owner()  # the Completed signal is trusted only from this sender
        rule = f"type='signal',interface='{PROMPT}',member='Completed',path='{prompt}'"
        self.conn.call(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch", "s", [rule]
        )
        self._call(prompt, PROMPT, "Prompt", "s", [""])
        try:
            msg = self.conn.wait_signal(prompt, PROMPT, "Completed", PROMPT_TIMEOUT, sender=self._owner)
        except DBusConnectionError as exc:
            raise Locked(f"{what}: the unlock prompt was not answered in time") from exc
        if msg.body and msg.body[0]:
            raise Locked(
                f"{what}: the unlock prompt was dismissed",
                fix="retry and enter the keyring password, or `keychain unlock`",
            )

    def _ensure_unlocked(self, path: str, what: str) -> None:
        collection = path if path.count("/") == 5 else path.rsplit("/", 1)[0]
        if not self._prop(collection, COLLECTION, "Locked"):
            return
        _unlocked, prompt = self._call(SERVICE_PATH, SERVICE, "Unlock", "ao", [[collection]])
        self._complete_prompt(prompt, what)

    # ── our items ────────────────────────────────────────────────────────────

    def _find(self, ref: Ref) -> list[str]:
        """Our items for ``ref``, oldest first, so concurrent writers agree on which one is kept."""
        attrs = {"xdg:schema": SCHEMA, "service": ref.service, "account": ref.account}
        candidates = self._call(self.collection(), COLLECTION, "SearchItems", "a{ss}", [attrs])[0]
        found = []
        for p in candidates:
            try:
                item_attrs = self._prop(p, ITEM, "Attributes", vanishable=True)
            except NotFound:
                continue  # deleted by a concurrent writer between search and read
            # Re-check exactly: a provider that matches loosely (case-insensitively, by prefix)
            # must not let `TG-CLI/x` act on `tg-cli/x`, which policy treats as another namespace.
            if {k: v for k, v in item_attrs.items() if k in attrs} == attrs:
                found.append(p)
        return sorted(found, key=_item_order)

    def _require(self, ref: Ref) -> str:
        found = self._find(ref)
        if not found:
            raise NotFound(f"no secret {ref}", fix=f"store it: keychain set {ref}")
        return found[0]

    def get(self, ref: Ref) -> bytes:
        self._ensure_unlocked(self.collection(), f"reading {ref}")
        item = self._require(ref)
        try:
            secret = self._call(item, ITEM, "GetSecret", "o", [self.session], vanishable=True)[0]
        except NotFound as exc:  # deleted between search and read: same answer as "not there"
            raise NotFound(f"no secret {ref}") from exc
        return bytes(secret[2])

    def set(self, ref: Ref, value: bytes, label: str | None, note: str | None) -> None:
        collection = self.collection()
        self._ensure_unlocked(collection, f"storing {ref}")
        for _attempt in range(3):
            found = self._find(ref)
            if not found:
                self._create(collection, ref, value, label, note)
            else:
                try:
                    self._update(found[0], value, label, note)
                except NotFound:
                    continue  # the item vanished under a concurrent delete: start over
            # Concurrent creates can leave several items; every writer keeps the oldest one, so
            # they converge on exactly one item instead of deleting each other's. An update of a
            # single existing item cannot have created a duplicate, so skip the second search.
            if found and len(found) == 1:
                return
            for extra in self._find(ref)[1:]:
                with contextlib.suppress(NotFound):
                    self._delete_item(extra, ref)
            return
        raise BackendError(f"storing {ref} kept racing with concurrent deletes")

    def _update(self, item: str, value: bytes, label: str | None, note: str | None) -> None:
        self._call(item, ITEM, "SetSecret", "(oayays)", [self._secret_struct(value)], vanishable=True)
        if note is not None:
            attrs = dict(self._prop(item, ITEM, "Attributes", vanishable=True))
            if note:
                attrs["note"] = note
            else:
                attrs.pop("note", None)
            self._call(
                item, PROPS, "Set", "ssv", [ITEM, "Attributes", Variant("a{ss}", attrs)], vanishable=True
            )
        if label is not None:
            self._call(item, PROPS, "Set", "ssv", [ITEM, "Label", Variant("s", label)], vanishable=True)

    def _create(self, collection: str, ref: Ref, value: bytes, label: str | None, note: str | None) -> None:
        attrs = {"xdg:schema": SCHEMA, "service": ref.service, "account": ref.account}
        if note:
            attrs["note"] = note
        props = {
            f"{ITEM}.Label": Variant("s", label or str(ref)),
            f"{ITEM}.Attributes": Variant("a{ss}", attrs),
        }
        _item, prompt = self._call(
            collection, COLLECTION, "CreateItem", "a{sv}(oayays)b", [props, self._secret_struct(value), False]
        )
        self._complete_prompt(prompt, f"storing {ref}")

    def _delete_item(self, item: str, ref: Ref) -> None:
        prompt = self._call(item, ITEM, "Delete", vanishable=True)[0]
        self._complete_prompt(prompt, f"deleting {ref}")

    def delete(self, ref: Ref) -> None:
        self._ensure_unlocked(self.collection(), f"deleting {ref}")
        found = self._find(ref)
        if not found:
            raise NotFound(f"no secret {ref}")
        for item in found:
            with contextlib.suppress(NotFound):  # a concurrent delete got there first
                self._delete_item(item, ref)

    def _info(self, item: str) -> ItemInfo | None:
        """Metadata of one of our items; None for foreign items and items deleted meanwhile."""
        try:
            props = self._call(item, PROPS, "GetAll", "s", [ITEM], vanishable=True)[0]
        except NotFound:
            return None
        attrs = props.get("Attributes", {})
        if attrs.get("xdg:schema") != SCHEMA or "service" not in attrs or "account" not in attrs:
            return None
        return ItemInfo(
            ref=Ref(attrs["service"], attrs["account"]),
            label=props.get("Label", ""),
            note=attrs.get("note", ""),
            created=props.get("Created") or None,
            modified=props.get("Modified") or None,
        )

    def info(self, ref: Ref) -> ItemInfo:
        info = self._info(self._require(ref))
        if info is None:
            raise NotFound(f"no secret {ref}")
        return info

    def list(self, service: str | None = None) -> list[ItemInfo]:
        attrs = {"xdg:schema": SCHEMA}
        if service:
            attrs["service"] = service
        items = self._call(self.collection(), COLLECTION, "SearchItems", "a{ss}", [attrs])[0]
        infos = [
            i
            for i in (self._info(p) for p in items)
            if i is not None and (not service or i.ref.service == service)
        ]
        return sorted(infos, key=lambda i: str(i.ref))

    # ── system items ─────────────────────────────────────────────────────────

    def system_list(self, query: dict[str, str]) -> list[SystemItem]:
        unlocked, locked = self._call(SERVICE_PATH, SERVICE, "SearchItems", "a{ss}", [dict(query)])
        out = []
        for path in [*unlocked, *locked]:
            if not path.startswith(COLLECTION_PREFIX):
                continue
            props = self._call(path, PROPS, "GetAll", "s", [ITEM])[0]
            attrs = props.get("Attributes", {})
            if attrs.get("xdg:schema") == SCHEMA:
                continue
            out.append(
                SystemItem(
                    id=path[len(COLLECTION_PREFIX) :],
                    label=props.get("Label", ""),
                    kind=attrs.get("xdg:schema", ""),
                    attributes=safe_attributes(attrs),
                    locked=bool(props.get("Locked", path in locked)),
                )
            )
        return sorted(out, key=lambda s: s.id)

    def system_get(self, ident: str) -> bytes:
        if not _ID_RE.fullmatch(ident):
            raise UsageError(
                f"invalid Secret Service item id {ident!r}",
                fix="use an id from `keychain system list`, e.g. login/12",
            )
        path = COLLECTION_PREFIX + ident
        self._ensure_unlocked(path, f"reading system:{ident}")
        if self._prop(path, ITEM, "Attributes").get("xdg:schema") == SCHEMA:
            # Reading our own item by id would sidestep the namespace check on its ref.
            raise UsageError(f"system:{ident} is a keychain-cli item; address it by its service/account ref")
        secret = self._call(path, ITEM, "GetSecret", "o", [self.session], vanishable=True)[0]
        return bytes(secret[2])

    # ── unlock and status ────────────────────────────────────────────────────

    def _owner_is_gnome_keyring(self) -> bool:
        try:
            pid = self.conn.call(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixProcessID",
                "s",
                [BUS],
            )[0]
            with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                return fh.read().strip().startswith("gnome-keyring")
        except (DBusError, DBusConnectionError, OSError):
            return False

    def _read_password(self, prompt: str, confirm: bool) -> bytes:
        if not sys.stdin.isatty():
            raise UsageError(
                "`keychain unlock` reads the keyring password from a terminal",
                why="stdin is not a TTY; a password must never travel via argv "
                "or a pipe from another agent's context",
                fix="run it in an interactive terminal (ssh -t host keychain unlock)",
            )
        first = getpass.getpass(prompt)
        if confirm and getpass.getpass("Repeat: ") != first:
            raise UsageError("the passwords do not match")
        return first.encode("utf-8")

    def unlock(self, create: bool = False) -> str:
        try:
            collection = self.collection()
        except BackendUnavailable:
            if not create:
                raise
            return self._create_default()
        if not self._prop(collection, COLLECTION, "Locked"):
            return f"{self._prop(collection, COLLECTION, 'Label')}: already unlocked"
        if sys.stdin.isatty() and self._owner_is_gnome_keyring():
            password = self._read_password("Keyring password: ", confirm=False)
            try:
                self._call(
                    SERVICE_PATH,
                    GNOME,
                    "UnlockWithMasterPassword",
                    "o(oayays)",
                    [collection, self._secret_struct(password)],
                )
            except (BackendError, PolicyDenied) as exc:
                raise Locked("the keyring did not unlock", why="wrong password?") from exc
            if self._prop(collection, COLLECTION, "Locked"):
                raise Locked("the keyring did not unlock", why="wrong password?")
            return f"{self._prop(collection, COLLECTION, 'Label')}: unlocked"
        _unlocked, prompt = self._call(SERVICE_PATH, SERVICE, "Unlock", "ao", [[collection]])
        self._complete_prompt(prompt, "unlocking the keyring")
        return f"{self._prop(collection, COLLECTION, 'Label')}: unlocked"

    def _create_default(self) -> str:
        if not self._owner_is_gnome_keyring():
            raise BackendUnavailable(
                "creating a keyring without a GUI needs gnome-keyring",
                fix="create the default collection in your keyring app",
            )
        password = self._read_password("New keyring password: ", confirm=True)
        props = {f"{COLLECTION}.Label": Variant("s", "Login")}
        path = self._call(
            SERVICE_PATH,
            GNOME,
            "CreateWithMasterPassword",
            "a{sv}(oayays)",
            [props, self._secret_struct(password)],
        )[0]
        self._call(SERVICE_PATH, SERVICE, "SetAlias", "so", ["default", path])
        self._collection = path
        return "created the default keyring 'Login'"

    def status(self) -> dict:
        out: dict = {
            "backend": self.name,
            "bus": self.address
            or os.environ.get("DBUS_SESSION_BUS_ADDRESS", "(derived from XDG_RUNTIME_DIR)"),
            "display": has_display(),
            "prompts": self.interactive,
        }
        try:
            _ = self.conn
            out["bus_reachable"] = True
        except BackendUnavailable as exc:
            out["bus_reachable"] = False
            out["error"] = exc.what
            return out
        try:
            collections = []
            default = self._call(SERVICE_PATH, SERVICE, "ReadAlias", "s", ["default"])[0]
            for path in self._collections():
                collections.append(
                    {
                        "id": path.rsplit("/", 1)[-1],
                        "label": self._prop(path, COLLECTION, "Label"),
                        "locked": bool(self._prop(path, COLLECTION, "Locked")),
                        "default": path == default,
                    }
                )
            out["service"] = True
            out["provider"] = "gnome-keyring" if self._owner_is_gnome_keyring() else "other"
            out["collections"] = collections
            out["default"] = None if default == NO_PROMPT else default.rsplit("/", 1)[-1]
        except BackendUnavailable as exc:
            out["service"] = False
            out["error"] = exc.what
        return out
