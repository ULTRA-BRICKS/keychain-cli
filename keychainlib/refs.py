"""Secret references: ``service/account`` for keychain-cli items, ``system:<id>`` for others.

The charset is deliberately narrow: refs travel through argv, policy globs, audit lines and
(on macOS) a `security -i` command line, so no whitespace, quotes or backslashes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import UsageError

SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
ACCOUNT_RE = re.compile(r"[A-Za-z0-9_@+][A-Za-z0-9._@+:-]{0,127}")
SYSTEM_PREFIX = "system:"
SYSTEM_ID_RE = re.compile(r"[A-Za-z0-9._@+:/%-]{1,512}")


@dataclass(frozen=True)
class Ref:
    service: str
    account: str

    def __str__(self) -> str:
        return f"{self.service}/{self.account}"


@dataclass(frozen=True)
class SystemRef:
    """An item keychain-cli did not create (a website, Wi-Fi or app password)."""

    id: str

    def __str__(self) -> str:
        return f"{SYSTEM_PREFIX}{self.id}"


def valid_service(name: str) -> bool:
    return SERVICE_RE.fullmatch(name) is not None


def parse_ref(text: str) -> Ref | SystemRef:
    if text.startswith(SYSTEM_PREFIX):
        ident = text[len(SYSTEM_PREFIX) :]
        if not SYSTEM_ID_RE.fullmatch(ident):
            raise UsageError("invalid system item id", fix="copy the id from `keychain system list`")
        return SystemRef(ident)
    service, sep, account = text.partition("/")
    if not sep or not SERVICE_RE.fullmatch(service) or not ACCOUNT_RE.fullmatch(account):
        # The rejected text is not echoed: a value pasted where a ref belongs must not be
        # printed a second time.
        raise UsageError(
            "invalid secret ref",
            why="a ref is SERVICE/ACCOUNT: service [A-Za-z0-9._-] (64 max), account "
            "[A-Za-z0-9._@+:-] (128 max), neither starting with '.' or '-'",
            fix="e.g. `tg-cli/bot-token` or `3d-cli/thingiverse`",
        )
    return Ref(service, account)


def parse_item_ref(text: str) -> Ref:
    ref = parse_ref(text)
    if isinstance(ref, SystemRef):
        raise UsageError(
            f"{text!r} is a system item; this command manages keychain-cli items only",
            fix="read system items with `keychain system get` or `keychain exec`",
        )
    return ref
