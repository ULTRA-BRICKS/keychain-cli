"""A secret value that refuses to print itself.

``str()``, ``repr()``, f-strings, logging and tracebacks all see ``Secret(***)``; the value is
reachable only through an explicit ``reveal()``. Pickling is refused so a secret cannot be
serialized to disk by accident. Python cannot zero immutable memory, so this guards against
accidental disclosure, not against a debugger attached to the process.
"""

from __future__ import annotations

import hmac


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: bytes | str) -> None:
        self._value = value.encode("utf-8") if isinstance(value, str) else bytes(value)

    def reveal(self) -> str:
        """The value as text (UTF-8). Use only where the value must leave the process."""
        return self._value.decode("utf-8")

    def reveal_bytes(self) -> bytes:
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return "Secret(***)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return id(self)

    def __reduce__(self) -> tuple:
        raise TypeError("a Secret cannot be pickled")
