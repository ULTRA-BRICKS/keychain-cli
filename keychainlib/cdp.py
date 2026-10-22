"""A minimal Chrome DevTools Protocol client on the stdlib: a WebSocket (RFC 6455) client plus
request/response matching with flattened target sessions.

It exists for `keychain fill` and `keychain capture`, which must move a secret between the
store and a browser field without the value leaving this process: no Playwright, no
`websocat`, no helper that would see the value in its argv or memory.

Only loopback endpoints are accepted, and on Linux the process listening on the other end of
the socket must run as our uid: on a shared machine another user could otherwise open a fake
"browser" on a loopback port and receive every value we type into it.

Nothing here logs a message body; error texts carry the CDP method name and the browser's
error message, never request parameters.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from .errors import BackendUnavailable, KeychainError, PolicyDenied, UsageError

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_MESSAGE = 256 * 1024 * 1024
CALL_TIMEOUT = 15.0


class CdpCallError(KeychainError):
    """The browser answered a CDP call with an error."""

    def __init__(self, method: str, message: str) -> None:
        super().__init__(f"the browser refused {method}", why=message)
        self.method = method
        self.message = message


def _loopback_host(host: str) -> str:
    if host == "localhost":
        return "127.0.0.1"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise PolicyDenied(
        "the CDP endpoint is not on this machine's loopback interface",
        why="a fill types a secret into whatever answers on that endpoint",
        fix="pass http://127.0.0.1:PORT or the ws://127.0.0.1:PORT/devtools/browser/… URL",
    )


def _browser_ws_url(cdp: str) -> tuple[str, int, str]:
    """(host, port, path) of the browser-level WebSocket for ``http://…`` or ``ws://…``."""
    try:
        parts = urlsplit(cdp)
        port = parts.port
    except ValueError as exc:
        raise UsageError("invalid --cdp URL") from exc
    if parts.scheme not in ("http", "ws") or not parts.hostname or not port:
        raise UsageError(
            "--cdp must be http://127.0.0.1:PORT or ws://127.0.0.1:PORT/devtools/…",
            why="TLS endpoints (https/wss) are not supported: CDP listens on loopback in clear",
        )
    host = _loopback_host(parts.hostname)
    if parts.scheme == "ws":
        return host, port, parts.path or "/"
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/json/version")
        resp = conn.getresponse()
        body = resp.read(1 << 20)
        conn.close()
        ws = json.loads(body)["webSocketDebuggerUrl"]
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        raise BackendUnavailable(
            f"no browser DevTools endpoint at {host}:{port}",
            why=type(exc).__name__,
            fix="start the browser with --remote-debugging-port, or pass the ws:// URL",
        ) from exc
    # Keep the host we validated: the advertised URL may name another interface.
    return host, port, urlsplit(ws).path


Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _plain(address: Address) -> Address:
    """``::ffff:127.0.0.1`` as ``127.0.0.1``: a dual-stack IPv6 listener sees an IPv4 peer so."""
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def _proc_endpoint(field: str) -> tuple[Address, int]:
    """Decode ``0100007F:1F90`` from /proc/net/tcp{,6}: the address is a sequence of 32-bit
    words in host byte order, the port is big-endian hex."""
    addr, port = field.split(":")
    raw = bytes.fromhex(addr)
    if sys.byteorder == "little":
        raw = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return _plain(ipaddress.ip_address(raw)), int(port, 16)


def _endpoint(name: tuple) -> tuple[Address, int]:
    return _plain(ipaddress.ip_address(name[0].split("%", 1)[0])), name[1]


def _peer_uid(sock: socket.socket) -> int | None:
    """The uid owning the other end of a loopback TCP connection: the row of /proc/net/tcp{,6}
    whose local end is our peer and whose remote end is us. Both tables are read: an IPv6
    listener on ``::`` accepts our IPv4 connection as ``::ffff:127.0.0.1``. The row may still be
    SYN_RECV (our connect() can return before the server has taken the last ACK); the kernel
    shows the listening socket's owner for it."""
    ours, theirs = _endpoint(sock.getsockname()), _endpoint(sock.getpeername())
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table, encoding="ascii") as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            live = len(cols) > 7 and cols[3] in ("01", "03")  # TCP_ESTABLISHED, TCP_SYN_RECV
            if live and _proc_endpoint(cols[1]) == theirs and _proc_endpoint(cols[2]) == ours:
                return int(cols[7])
    return None


def _check_peer(sock: socket.socket) -> None:
    if not sys.platform.startswith("linux"):
        return  # no /proc/net: on macOS loopback ports are not attributed (see SPEC)
    uid = _peer_uid(sock)
    if uid != os.getuid():
        raise PolicyDenied(
            "the CDP endpoint is not owned by this user",
            why=f"the listening process runs as uid {uid}" if uid is not None else "its owner is unknown",
            fix="connect to a browser you started yourself",
        )


class WebSocket:
    def __init__(self, host: str, port: int, path: str, timeout: float = CALL_TIMEOUT) -> None:
        try:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise BackendUnavailable(
                f"cannot connect to the browser at {host}:{port}", why=exc.strerror or type(exc).__name__
            ) from exc
        self._buf = b""
        try:
            _check_peer(self.sock)
            self._handshake(host, port, path)
        except BaseException:
            self.sock.close()
            raise

    def _handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        hostport = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self._send(request.encode("ascii"))
        while b"\r\n\r\n" not in self._buf:
            self._fill()
            if len(self._buf) > 65536:
                raise BackendUnavailable("the browser sent an oversized WebSocket handshake")
        head, self._buf = self._buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        headers = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in lines[1:])}
        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        if " 101 " not in lines[0] + " " or headers.get("sec-websocket-accept") != accept:
            raise BackendUnavailable("the CDP endpoint refused the WebSocket upgrade", why=lines[0])

    def _fill(self) -> None:
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError as exc:
            raise BackendUnavailable("the browser did not answer in time") from exc
        except OSError as exc:
            raise BackendUnavailable("the browser connection failed", why=type(exc).__name__) from exc
        if not chunk:
            raise BackendUnavailable("the browser closed the DevTools connection")
        self._buf += chunk

    def _take(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._fill()
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        n = len(payload)
        if n < 126:
            header = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < 1 << 16:
            header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self._send(header + mask + masked)

    def _send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except TimeoutError as exc:
            raise BackendUnavailable("the browser did not accept data in time") from exc
        except OSError as exc:  # a closed browser: BrokenPipe/ConnectionReset, not "success"
            raise BackendUnavailable("the browser connection failed", why=type(exc).__name__) from exc

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def recv_text(self) -> str:
        parts: list[bytes] = []
        size = 0
        while True:
            b0, b1 = self._take(2)
            fin, opcode, n = b0 & 0x80, b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._take(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._take(8))[0]
            mask = self._take(4) if b1 & 0x80 else b""
            size += n
            if size > _MAX_MESSAGE:
                raise BackendUnavailable("the browser sent an oversized DevTools message")
            payload = self._take(n)
            if mask:
                payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise BackendUnavailable("the browser closed the DevTools connection")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                size -= n
                continue
            if opcode == 0xA:
                size -= n
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8")

    def close(self) -> None:
        with contextlib.suppress(OSError, BackendUnavailable):
            self._send_frame(0x8, b"")
        self.sock.close()


class Cdp:
    """One browser-level connection. ``call`` takes an optional flattened ``session`` id."""

    supports_sessions = True

    def __init__(self, ws: WebSocket) -> None:
        self.ws = ws
        self._next = 0
        self.events: list[tuple[str, dict, str | None]] = []
        self.attached: list[str] = []  # sessions we opened (see detach_attached)

    @classmethod
    def connect(cls, cdp_url: str) -> Cdp:
        return cls(WebSocket(*_browser_ws_url(cdp_url)))

    def call(self, method: str, params: dict | None = None, session: str | None = None) -> dict:
        self._next += 1
        msg_id = self._next
        msg: dict = {"id": msg_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send_text(json.dumps(msg))
        deadline = time.monotonic() + CALL_TIMEOUT
        while True:
            if time.monotonic() > deadline:
                raise BackendUnavailable(f"the browser did not answer {method}")
            reply = json.loads(self.ws.recv_text())
            if reply.get("id") == msg_id:
                if "error" in reply:
                    raise CdpCallError(method, str(reply["error"].get("message", "")))
                return reply.get("result", {})
            if "method" in reply:
                self.events.append((reply["method"], reply.get("params", {}), reply.get("sessionId")))

    def take_events(self, method: str, session: str | None) -> list[tuple[dict, str | None]]:
        """Remove and return the ``method`` events that arrived on ``session``; events for
        other sessions stay queued for their own consumer."""
        mine = [(p, s) for m, p, s in self.events if m == method and s == session]
        self.events = [e for e in self.events if not (e[0] == method and e[2] == session)]
        return mine

    def watch(self, method: str) -> bool:
        """Events reach us on this connection without subscribing."""
        return True

    def attach(self, target_id: str) -> str:
        session = self.call("Target.attachToTarget", {"targetId": target_id, "flatten": True})["sessionId"]
        self.attached.append(session)
        return session

    def detach_attached(self, since: int = 0) -> None:
        """Detach the sessions ``attach`` opened (those after the first ``since``), for a
        connection the caller keeps using: their overrides (focus emulation, auto-attach and its
        child sessions) end with them. Sessions the caller opened itself are left alone."""
        while len(self.attached) > since:
            with contextlib.suppress(CdpCallError, BackendUnavailable):
                self.call("Target.detachFromTarget", {"sessionId": self.attached.pop()})

    def close(self) -> None:
        self.ws.close()


class SessionCdp:
    """Adapter for a CDP session someone else already holds, e.g. Playwright's sync
    ``page.context.new_cdp_session(page)``: anything with ``send(method, params) -> dict`` and,
    for events, ``on(event, handler)``. It is bound to one page, so frames in other renderer
    processes (cross-site iframes) are not reachable through it; those are refused as unknown
    frames. Without ``on`` the TLS state cannot be read, so a fill through it is refused."""

    supports_sessions = False

    def __init__(
        self,
        sender: Callable[[str, dict], dict],
        subscribe: Callable[[str, Callable[[dict], None]], object] | None = None,
    ) -> None:
        self._send = sender
        self._subscribe = subscribe
        self._watched: set[str] = set()
        self._open = True
        self.events: list[tuple[str, dict]] = []

    def call(self, method: str, params: dict | None = None, session: str | None = None) -> dict:
        if session is not None:
            raise UsageError("this CDP session cannot address other targets")
        try:
            return self._send(method, params or {}) or {}
        except KeychainError:
            raise
        except Exception as exc:  # noqa: BLE001 - the adapter's own error types are unknown here
            # Only the type: an adapter's message could quote the request, value included.
            raise CdpCallError(method, type(exc).__name__) from None

    def watch(self, method: str) -> bool:
        if self._subscribe is None:
            return False
        if method not in self._watched:
            self._subscribe(method, lambda params, m=method: self._event(m, params))
            self._watched.add(method)
        return True

    def _event(self, method: str, params: dict | None) -> None:
        if self._open:  # the caller's session outlives us; its handlers stay registered
            self.events.append((method, params or {}))

    def take_events(self, method: str, session: str | None = None) -> list[tuple[dict, None]]:
        mine = [(p, None) for m, p in self.events if m == method]
        self.events = [e for e in self.events if e[0] != method]
        return mine

    def close(self) -> None:
        """Stop collecting events; the session itself is the caller's to close."""
        self._open = False
        self.events.clear()
