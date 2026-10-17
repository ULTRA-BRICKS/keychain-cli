"""Secret-store backends and the shared data shapes they return.

A backend only stores and fetches; policy, audit and the never-print rules live above it in
`keychainlib.api` / `keychainlib.cli`. There is deliberately no file backend: a secret store
that writes values to disk in the clear is the thing this tool exists to replace.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from ..errors import BackendUnavailable
from ..refs import Ref

# Attribute names that are metadata, never values, and so are safe to show in `system list`.
# Everything else is hidden: some apps keep secrets in attributes (passwords-app stores TOTP
# seeds in `otpauth`), and "list never prints a secret" must hold for items we did not write.
SAFE_SYSTEM_ATTRIBUTES = frozenset(
    {
        "xdg:schema",
        "application",
        "type",
        "url",
        "uri",
        "server",
        "host",
        "domain",
        "port",
        "protocol",
        "authtype",
        "path",
        "username",
        "user",
        "account",
        "service",
        "origin_url",
        "action_url",
        "signon_realm",
        "username_value",
        "group",
        "title",
        # macOS keychain attribute codes
        "srvr",
        "acct",
        "svce",
        "ptcl",
        "sdmn",
        "desc",
        "labl",
        "atyp",
    }
)


@dataclass(frozen=True)
class ItemInfo:
    ref: Ref
    label: str = ""
    note: str = ""
    created: int | None = None
    modified: int | None = None

    def as_dict(self) -> dict:
        return {
            "ref": str(self.ref),
            "service": self.ref.service,
            "account": self.ref.account,
            "label": self.label,
            "note": self.note,
            "created": self.created,
            "modified": self.modified,
        }


@dataclass(frozen=True)
class SystemItem:
    id: str
    label: str = ""
    kind: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    locked: bool = False

    def as_dict(self) -> dict:
        return {
            "ref": f"system:{self.id}",
            "label": self.label,
            "kind": self.kind,
            "attributes": dict(self.attributes),
            "locked": self.locked,
        }


class Backend(Protocol):
    name: str

    def get(self, ref: Ref) -> bytes: ...
    def set(self, ref: Ref, value: bytes, label: str | None, note: str | None) -> None: ...
    def delete(self, ref: Ref) -> None: ...
    def info(self, ref: Ref) -> ItemInfo: ...
    def list(self, service: str | None = None) -> list[ItemInfo]: ...
    def system_list(self, query: dict[str, str]) -> list[SystemItem]: ...
    def system_get(self, ident: str) -> bytes: ...
    def unlock(self, create: bool = False) -> str: ...
    def status(self) -> dict: ...


_URL_ATTRIBUTES = frozenset({"url", "uri", "origin_url", "action_url", "signon_realm"})


def _strip_url(value: str) -> str:
    """Drop userinfo, query and fragment: URLs can carry `user:password@` or `?token=`."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    if not parts.scheme and not parts.netloc:
        return value.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))


def safe_attributes(attrs: dict[str, str]) -> dict[str, str]:
    return {
        k: _strip_url(v) if k in _URL_ATTRIBUTES else v
        for k, v in sorted(attrs.items())
        if k in SAFE_SYSTEM_ATTRIBUTES
    }


def default_backend(store: str | None = None, interactive: bool = True) -> Backend:
    """The OS store for this platform. ``store`` picks a Secret Service collection (Linux) or a
    keychain file (macOS); ``None`` means the default one."""
    if sys.platform == "darwin":
        from .macos import MacOSBackend

        return MacOSBackend(keychain=store)
    if sys.platform.startswith("linux") or "bsd" in sys.platform:
        from .secretservice import SecretServiceBackend

        return SecretServiceBackend(collection=store, interactive=interactive)
    raise BackendUnavailable(
        f"no secret store backend for platform {sys.platform!r}",
        why="keychain-cli supports macOS Keychain and the freedesktop "
        "Secret Service (GNOME Keyring, KWallet, KeePassXC)",
    )
