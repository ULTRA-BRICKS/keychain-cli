"""A minimal, stdlib-only D-Bus client: just enough wire protocol to talk to the Secret Service.

Why hand-rolled: the ecosystem rule is "stdlib-only at import" and the obvious alternatives
leak secrets. `secret-tool` is often absent and its `search` prints every value; `busctl` and
`gdbus` take the secret as a command-line argument, i.e. visible in /proc/<pid>/cmdline. Speaking
the protocol ourselves keeps the value inside this process and the session-bus socket.

Scope: the session bus over a unix socket, EXTERNAL auth, method calls, replies, errors and
signals (for Secret Service prompts). Little- and big-endian messages are read; we write
little-endian. Unix-fd passing is not supported (the Secret Service never needs it).
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

METHOD_CALL, METHOD_RETURN, ERROR, SIGNAL = 1, 2, 3, 4
NO_REPLY_EXPECTED = 0x1

# Header field codes (D-Bus specification, "Message Format").
F_PATH, F_INTERFACE, F_MEMBER, F_ERROR_NAME, F_REPLY_SERIAL = 1, 2, 3, 4, 5
F_DESTINATION, F_SENDER, F_SIGNATURE = 6, 7, 8

_FIXED = {
    "y": ("B", 1),
    "b": ("I", 4),
    "n": ("h", 2),
    "q": ("H", 2),
    "i": ("i", 4),
    "u": ("I", 4),
    "x": ("q", 8),
    "t": ("Q", 8),
    "d": ("d", 8),
    "h": ("I", 4),
}
_ALIGN = {"s": 4, "o": 4, "g": 1, "a": 4, "(": 8, "{": 8, "v": 1}
MAX_MESSAGE = 128 * 1024 * 1024  # the specification's hard limit


class DBusError(Exception):
    """A D-Bus error reply (``name`` is e.g. ``org.freedesktop.DBus.Error.ServiceUnknown``)."""

    def __init__(self, name: str, message: str = "") -> None:
        super().__init__(f"{name}: {message}" if message else name)
        self.name = name
        self.message = message


class DBusConnectionError(Exception):
    """The bus could not be reached or the connection broke."""


@dataclass(frozen=True)
class Variant:
    """A value with its explicit D-Bus signature, for marshalling ``v`` arguments."""

    signature: str
    value: Any


@dataclass
class Message:
    type: int
    serial: int
    fields: dict[int, Any] = field(default_factory=dict)
    body: list[Any] = field(default_factory=list)
    flags: int = 0

    @property
    def member(self) -> str | None:
        return self.fields.get(F_MEMBER)

    @property
    def interface(self) -> str | None:
        return self.fields.get(F_INTERFACE)

    @property
    def path(self) -> str | None:
        return self.fields.get(F_PATH)


# ── signatures ────────────────────────────────────────────────────────────────


def _complete_type_end(sig: str, start: int) -> int:
    """Index just past the single complete type that begins at ``sig[start]``."""
    ch = sig[start]
    if ch == "a":
        return _complete_type_end(sig, start + 1)
    if ch in "({":
        close = ")" if ch == "(" else "}"
        i = start + 1
        if i >= len(sig) or sig[i] == close:
            raise ValueError(f"empty struct or dict entry in {sig!r}")
        while i < len(sig) and sig[i] != close:
            i = _complete_type_end(sig, i)
        if i >= len(sig):
            raise ValueError(f"unterminated container in {sig!r}")
        return i + 1
    if ch in _FIXED or ch in "sogv":
        return start + 1
    raise ValueError(f"unsupported D-Bus type code {ch!r} in {sig!r}")


def split_signature(sig: str) -> list[str]:
    """Split a signature into its complete types: ``"sa{sv}o"`` -> ``["s", "a{sv}", "o"]``."""
    out, i = [], 0
    while i < len(sig):
        j = _complete_type_end(sig, i)
        out.append(sig[i:j])
        i = j
    return out


def _alignment(t: str) -> int:
    return _FIXED[t[0]][1] if t[0] in _FIXED else _ALIGN[t[0]]


# ── marshalling ───────────────────────────────────────────────────────────────


class _Writer:
    def __init__(self) -> None:
        self.buf = bytearray()

    def align(self, n: int) -> None:
        self.buf.extend(b"\0" * (-len(self.buf) % n))

    def write(self, t: str, value: Any) -> None:
        c = t[0]
        if c in _FIXED:
            fmt, size = _FIXED[c]
            self.align(size)
            if c == "b":
                value = 1 if value else 0
            self.buf.extend(struct.pack("<" + fmt, value))
        elif c in "so":
            data = value.encode("utf-8")
            self.align(4)
            self.buf.extend(struct.pack("<I", len(data)) + data + b"\0")
        elif c == "g":
            data = value.encode("ascii")
            self.buf.extend(struct.pack("<B", len(data)) + data + b"\0")
        elif c == "v":
            if not isinstance(value, Variant):
                raise TypeError("a 'v' argument must be a Variant")
            self.write("g", value.signature)
            self.write(value.signature, value.value)
        elif c == "a":
            self._write_array(t[1:], value)
        elif c == "(":
            self.align(8)
            for sub, item in zip(split_signature(t[1:-1]), value, strict=True):
                self.write(sub, item)
        else:
            raise ValueError(f"cannot marshal type {t!r}")

    def _write_array(self, elem: str, value: Any) -> None:
        self.align(4)
        len_pos = len(self.buf)
        self.buf.extend(b"\0\0\0\0")
        self.align(_alignment(elem))
        start = len(self.buf)
        if elem == "y":
            self.buf.extend(bytes(value))
        elif elem[0] == "{":
            key_t, val_t = split_signature(elem[1:-1])
            for k, v in value.items():
                self.align(8)
                self.write(key_t, k)
                self.write(val_t, v)
        else:
            for item in value:
                self.write(elem, item)
        struct.pack_into("<I", self.buf, len_pos, len(self.buf) - start)


def marshal(signature: str, values: list[Any]) -> bytes:
    w = _Writer()
    for t, v in zip(split_signature(signature), values, strict=True):
        w.write(t, v)
    return bytes(w.buf)


class _Reader:
    def __init__(self, data: bytes, endian: str, pos: int = 0) -> None:
        self.data = data
        self.e = endian
        self.pos = pos
        self.depth = 0

    def align(self, n: int) -> None:
        self.pos += -self.pos % n

    def _unpack(self, fmt: str, size: int) -> Any:
        if self.pos + size > len(self.data):
            raise DBusConnectionError("truncated D-Bus message")
        (value,) = struct.unpack_from(self.e + fmt, self.data, self.pos)
        self.pos += size
        return value

    def read(self, t: str) -> Any:
        c = t[0]
        if c in _FIXED:
            fmt, size = _FIXED[c]
            self.align(size)
            value = self._unpack(fmt, size)
            return bool(value) if c == "b" else value
        if c in "so":
            self.align(4)
            return self._string(self._unpack("I", 4), "utf-8")
        if c == "g":
            return self._string(self._unpack("B", 1), "ascii")
        if c == "v":
            self.depth += 1
            if self.depth > 64:  # the specification's nesting limit
                raise DBusConnectionError("D-Bus variant nesting too deep")
            try:
                return self.read(self.read("g"))
            finally:
                self.depth -= 1
        if c == "a":
            return self._read_array(t[1:])
        if c == "(":
            self.align(8)
            return tuple(self.read(sub) for sub in split_signature(t[1:-1]))
        raise ValueError(f"cannot unmarshal type {t!r}")

    def _read_array(self, elem: str) -> Any:
        self.align(4)
        n = self._unpack("I", 4)
        self.align(_alignment(elem))
        end = self.pos + n
        if end > len(self.data):
            raise DBusConnectionError("truncated D-Bus array")
        if elem == "y":
            raw = bytes(self.data[self.pos : end])
            self.pos = end
            return raw
        if elem[0] == "{":
            key_t, val_t = split_signature(elem[1:-1])
            out: dict[Any, Any] = {}
            while self.pos < end:
                self.align(8)
                k = self.read(key_t)
                out[k] = self.read(val_t)
            return out
        items = []
        while self.pos < end:
            before = self.pos
            items.append(self.read(elem))
            if self.pos == before:
                raise DBusConnectionError("D-Bus array element consumed no bytes")
        return items

    def _string(self, n: int, encoding: str) -> str:
        end = self.pos + n
        if end >= len(self.data) or self.data[end] != 0:
            raise DBusConnectionError("truncated or unterminated D-Bus string")
        raw = self.data[self.pos : end]
        self.pos = end + 1
        return raw.decode(encoding)


def unmarshal(signature: str, data: bytes, endian: str = "<") -> list[Any]:
    r = _Reader(data, endian)
    return [r.read(t) for t in split_signature(signature)]


def encode_message(msg: Message, signature: str = "") -> bytes:
    body = marshal(signature, msg.body) if signature else b""
    fields: list[tuple[int, Variant]] = []
    kinds = {
        F_PATH: "o",
        F_INTERFACE: "s",
        F_MEMBER: "s",
        F_ERROR_NAME: "s",
        F_REPLY_SERIAL: "u",
        F_DESTINATION: "s",
        F_SENDER: "s",
        F_SIGNATURE: "g",
    }
    for code, value in msg.fields.items():
        fields.append((code, Variant(kinds[code], value)))
    if signature:
        fields.append((F_SIGNATURE, Variant("g", signature)))
    w = _Writer()
    w.write("y", ord("l"))
    w.write("y", msg.type)
    w.write("y", msg.flags)
    w.write("y", 1)
    w.write("u", len(body))
    w.write("u", msg.serial)
    w.write("a(yv)", fields)
    w.align(8)
    return bytes(w.buf) + body


def decode_message(data: bytes) -> Message:
    endian = {ord("l"): "<", ord("B"): ">"}.get(data[0])
    if endian is None:
        raise DBusConnectionError("bad D-Bus endianness marker")
    r = _Reader(data, endian, 4)
    body_len = r.read("u")
    serial = r.read("u")
    fields = dict(r.read("a(yv)"))
    r.align(8)
    body_data = data[r.pos : r.pos + body_len]
    sig = fields.get(F_SIGNATURE, "")
    body = unmarshal(sig, body_data, endian) if sig else []
    return Message(type=data[1], serial=serial, fields=fields, body=body, flags=data[2])


def message_length(head: bytes) -> int:
    """Total length of a message from its first 16 bytes."""
    endian = {ord("l"): "<", ord("B"): ">"}.get(head[0])
    if endian is None:
        raise DBusConnectionError("bad D-Bus endianness marker")
    body_len, _serial, fields_len = struct.unpack_from(endian + "III", head, 4)
    header = 16 + fields_len
    total = header + (-header % 8) + body_len
    if total > MAX_MESSAGE:
        raise DBusConnectionError("D-Bus message exceeds the maximum size")
    return total


# ── connection ────────────────────────────────────────────────────────────────


def session_bus_address() -> str:
    """The session bus address; falls back to the systemd user-bus socket for cron/ssh/systemd."""
    addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if addr:
        return addr
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return f"unix:path={runtime}/bus"


def _socket_target(address: str) -> str | bytes:
    for entry in address.split(";"):
        kind, _, params = entry.partition(":")
        if kind != "unix":
            continue
        opts = dict(p.split("=", 1) for p in params.split(",") if "=" in p)
        if "path" in opts:
            return _unescape_address(opts["path"])
        if "abstract" in opts:
            return b"\0" + _unescape_address(opts["abstract"]).encode()
    raise DBusConnectionError(f"no usable unix transport in bus address {address!r}")


def _unescape_address(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value):
            try:
                out.append(chr(int(value[i + 1 : i + 3], 16)))
            except ValueError:  # a malformed address is "no bus", not an internal error
                raise DBusConnectionError("malformed escape in the bus address") from None
            i += 3
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


class Connection:
    """One authenticated session-bus connection. Not thread-safe; one caller at a time."""

    def __init__(self, address: str | None = None, timeout: float = 25.0) -> None:
        self.timeout = timeout
        self._serial = 0
        self._buf = bytearray()
        self._pending: list[Message] = []
        address = address or session_bus_address()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(_socket_target(address))
        except OSError as exc:
            sock.close()
            raise DBusConnectionError(f"cannot connect to the session bus ({exc.strerror or exc})") from exc
        self.sock = sock
        try:
            _check_peer_uid(sock)
            self._authenticate()
            self.unique_name = self.call(
                "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello"
            )[0]
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _authenticate(self) -> None:
        uid_hex = str(os.getuid()).encode().hex()
        self.sock.sendall(b"\0AUTH EXTERNAL " + uid_hex.encode() + b"\r\n")
        line = self._read_line()
        if not line.startswith(b"OK "):
            raise DBusConnectionError("session bus refused EXTERNAL authentication")
        self.sock.sendall(b"BEGIN\r\n")

    def _read_line(self) -> bytes:
        while b"\r\n" not in self._buf:
            if len(self._buf) > 16384:
                raise DBusConnectionError("oversized D-Bus authentication line")
            self._recv()
        line, _, rest = bytes(self._buf).partition(b"\r\n")
        self._buf = bytearray(rest)
        return line

    def _recv(self) -> None:
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError as exc:
            raise DBusConnectionError("timed out waiting for the session bus") from exc
        except OSError as exc:
            raise DBusConnectionError(f"session bus connection failed ({exc})") from exc
        if not chunk:
            raise DBusConnectionError("session bus closed the connection")
        self._buf.extend(chunk)

    def _read_message(self, deadline: float) -> Message:
        while len(self._buf) < 16:
            self._recv_until(deadline)
        total = message_length(bytes(self._buf[:16]))
        while len(self._buf) < total:
            self._recv_until(deadline)
        data = bytes(self._buf[:total])
        del self._buf[:total]
        try:
            return decode_message(data)
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            UnicodeDecodeError,
            struct.error,
            RecursionError,
        ) as exc:
            raise DBusConnectionError("malformed D-Bus message") from exc

    def _recv_until(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DBusConnectionError("timed out waiting for a D-Bus reply")
        self.sock.settimeout(remaining)
        self._recv()

    def send(self, msg: Message, signature: str = "") -> int:
        self._serial += 1
        msg.serial = self._serial
        self.sock.sendall(encode_message(msg, signature))
        return msg.serial

    def call(
        self,
        destination: str,
        path: str,
        interface: str,
        member: str,
        signature: str = "",
        args: list[Any] | None = None,
        timeout: float | None = None,
    ) -> list[Any]:
        msg = Message(
            METHOD_CALL,
            0,
            {F_PATH: path, F_INTERFACE: interface, F_MEMBER: member, F_DESTINATION: destination},
            list(args or []),
        )
        serial = self.send(msg, signature)
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while True:
            reply = self._read_message(deadline)
            if reply.fields.get(F_REPLY_SERIAL) == serial:
                if reply.type == ERROR:
                    text = reply.body[0] if reply.body and isinstance(reply.body[0], str) else ""
                    raise DBusError(reply.fields.get(F_ERROR_NAME, "unknown"), text)
                return reply.body
            if reply.type == SIGNAL:
                self._queue_signal(reply)

    def _queue_signal(self, msg: Message) -> None:
        self._pending.append(msg)
        del self._pending[:-256]  # signals we never wait for must not grow without bound

    def wait_signal(
        self, path: str, interface: str, member: str, timeout: float, sender: str | None = None
    ) -> Message:
        """Block until a matching signal arrives (match rule must already be added). With
        ``sender``, only a signal from that unique bus name counts."""
        deadline = time.monotonic() + timeout
        while True:
            for i, sig in enumerate(self._pending):
                if (sig.path, sig.interface, sig.member) == (path, interface, member) and (
                    sender is None or sig.fields.get(F_SENDER) == sender
                ):
                    return self._pending.pop(i)
            self._queue_signal(self._read_message(deadline))


def _check_peer_uid(sock: socket.socket) -> None:
    """The `plain` Secret Service session is acceptable only because the bus belongs to us:
    refuse a socket whose other end runs as another user (a stale or abstract bus address
    squatted by someone else). Linux only (SO_PEERCRED); elsewhere the socket path's
    permissions are the guard."""
    peercred = getattr(socket, "SO_PEERCRED", None)
    if peercred is None:
        return
    creds = sock.getsockopt(socket.SOL_SOCKET, peercred, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    if uid != os.getuid():
        raise DBusConnectionError(f"the session bus socket belongs to uid {uid}, not to us")
