"""In-memory backend for tests. Never selectable from the CLI or the environment: a store that
lives in a dict cannot leak to disk, and nothing outside a test can end up using it."""

from __future__ import annotations

import time

from ..errors import Locked, NotFound
from ..refs import Ref
from . import ItemInfo, SystemItem, safe_attributes


class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.items: dict[Ref, tuple[bytes, ItemInfo]] = {}
        self.system: dict[str, tuple[bytes, SystemItem]] = {}
        self.locked = False

    def _check(self) -> None:
        if self.locked:
            raise Locked("the fake keyring is locked", fix="keychain unlock")

    def get(self, ref: Ref) -> bytes:
        self._check()
        if ref not in self.items:
            raise NotFound(f"no secret {ref}")
        return self.items[ref][0]

    def set(
        self, ref: Ref, value: bytes, label: str | None, note: str | None, origin: str | None = None
    ) -> None:
        self._check()
        now = int(time.time())
        old = self.items.get(ref)
        info = ItemInfo(
            ref=ref,
            label=label if label is not None else (old[1].label if old else str(ref)),
            note=note if note is not None else (old[1].note if old else ""),
            origin=origin if origin is not None else (old[1].origin if old else ""),
            created=old[1].created if old else now,
            modified=now,
        )
        self.items[ref] = (bytes(value), info)

    def delete(self, ref: Ref) -> None:
        self._check()
        if self.items.pop(ref, None) is None:
            raise NotFound(f"no secret {ref}")

    def info(self, ref: Ref) -> ItemInfo:
        if ref not in self.items:
            raise NotFound(f"no secret {ref}")
        return self.items[ref][1]

    def list(self, service: str | None = None) -> list[ItemInfo]:
        return sorted((i for _, i in self.items.values()
                       if service is None or i.ref.service == service), key=lambda i: str(i.ref))

    def add_system(self, ident: str, value: bytes, label: str, attributes: dict[str, str]) -> None:
        self.system[ident] = (value, SystemItem(ident, label, attributes.get("xdg:schema", ""),
                                                safe_attributes(attributes)))

    def system_list(self, query: dict[str, str]) -> list[SystemItem]:
        out = []
        for _, item in self.system.values():
            if all(item.attributes.get(k) == v for k, v in query.items()):
                out.append(item)
        return out

    def system_info(self, ident: str) -> SystemItem:
        if ident not in self.system:
            raise NotFound(f"no system item {ident}")
        return self.system[ident][1]

    def system_get(self, ident: str) -> bytes:
        self._check()
        if ident not in self.system:
            raise NotFound(f"no system item {ident}")
        return self.system[ident][0]

    def ensure_unlocked(self, what: str, system_id: str | None = None) -> None:
        self._check()

    def unlock(self, create: bool = False) -> str:
        self.locked = False
        return "unlocked"

    def status(self) -> dict:
        return {"backend": self.name, "locked": self.locked, "items": len(self.items)}
