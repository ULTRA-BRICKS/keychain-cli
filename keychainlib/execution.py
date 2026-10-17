"""`keychain exec`: hand secrets to a child process without printing them.

Values go into the child's environment (``--env NAME=REF``) and/or its stdin (``--stdin REF``).
By default the child's stdout and stderr are piped through a redactor that replaces every
occurrence of an injected value with ``***``, so a child that echoes its token (a debug line, a
curl -v) still cannot put it into an agent transcript. ``--no-redact`` replaces this process
with the child (full TTY passthrough) for interactive programs.

The environment is visible to same-user processes via /proc/<pid>/environ — the same exposure
any env-configured tool already has; it never reaches argv, logs or disk.
"""

from __future__ import annotations

import base64
import json
import os
import re
import signal
import subprocess
import sys
import threading
from typing import BinaryIO
from urllib.parse import quote

from .errors import MissingDependency, UsageError
from .secret import Secret

MASK = b"***"
MIN_REDACT = 4  # shorter values would mask ordinary text; such secrets are refused below
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Redactor:
    """Streaming replace of secret values. A decision at position p is made only once every
    needle that could start at p is fully buffered (len(longest)-1 bytes are held back), so a
    value split across reads is caught and a short needle never pre-empts a longer one that
    contains it. At one position the longest needle wins."""

    def __init__(self, needles: list[bytes]) -> None:
        self.needles = sorted({n for n in needles if n}, key=len, reverse=True)
        self.keep = max((len(n) for n in self.needles), default=1) - 1
        self.buf = b""

    def _emit(self, limit: int) -> bytes:
        buf, out, i = self.buf, bytearray(), 0
        while i < limit:
            best: tuple[int, bytes] | None = None
            for needle in self.needles:  # longest first, so `<` keeps the longest at a tie
                p = buf.find(needle, i)
                if p != -1 and p < limit and (best is None or p < best[0]):
                    best = (p, needle)
            if best is None:
                out += buf[i:limit]
                i = limit
                break
            p, needle = best
            out += buf[i:p] + MASK
            i = p + len(needle)
        self.buf = buf[i:]
        return bytes(out)

    def feed(self, chunk: bytes) -> bytes:
        self.buf += chunk
        return self._emit(len(self.buf) - self.keep)

    def flush(self) -> bytes:
        return self._emit(len(self.buf))


def _base64_cores(value: bytes) -> list[bytes]:
    """The base64 characters that depend only on ``value``, at each of the three byte offsets
    it can start at inside a larger encoded blob (e.g. ``user:password`` in Basic auth)."""
    out = []
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + value)
        start = -(-8 * k // 6)  # first 6-bit group that lies wholly inside value
        end = (8 * (k + len(value))) // 6  # one past the last such group
        core = enc[start:end]
        if len(core) >= MIN_REDACT * 2:
            out += [core, core.translate(bytes.maketrans(b"+/", b"-_"))]
    return out


def variants(value: bytes) -> list[bytes]:
    """Forms in which a child commonly prints a value: raw and trimmed, base64 (as in HTTP
    Basic auth), URL-quoted, JSON/Python-escaped, hex, and each line of a multi-line value."""
    out = [value, value.strip()]
    out += _base64_cores(value)
    out.append(quote(value, safe="").encode())
    try:
        out.append(json.dumps(value.decode("utf-8"))[1:-1].encode())
        out.append(json.dumps(value.decode("utf-8"), ensure_ascii=False)[1:-1].encode())
    except UnicodeDecodeError:
        pass
    out.append(repr(value)[2:-1].encode())
    out += [value.hex().encode(), value.hex().upper().encode()]
    lines = value.splitlines()
    if len(lines) > 1:
        out += [line for line in lines if len(line.strip()) >= 8]
    return [v for v in dict.fromkeys(out) if len(v) >= MIN_REDACT]


def valid_env_name(name: str) -> bool:
    return _ENV_NAME.fullmatch(name) is not None


def _pump(src: BinaryIO, dst: BinaryIO, redactor: Redactor) -> None:
    try:
        while True:
            chunk = os.read(src.fileno(), 65536)
            if not chunk:
                break
            out = redactor.feed(chunk)
            if out:
                dst.write(out)
                dst.flush()
        tail = redactor.flush()
        if tail:
            dst.write(tail)
            dst.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass  # our reader went away (`| head`): fall through and close the child's pipe
    finally:
        # Closing our end gives the child EPIPE/SIGPIPE instead of a full pipe it blocks on.
        src.close()


def run(
    argv: list[str], env_secrets: dict[str, Secret], stdin_secret: Secret | None, redact: bool = True
) -> int:
    if not argv:
        raise UsageError("no command given", fix="keychain exec --env NAME=REF -- command args")
    for name in env_secrets:
        if not valid_env_name(name):
            raise UsageError("invalid environment variable name")
    secrets = [*env_secrets.values(), *([stdin_secret] if stdin_secret else [])]
    if redact and any(len(s) < MIN_REDACT for s in secrets):
        raise UsageError(
            f"a secret shorter than {MIN_REDACT} bytes cannot be masked reliably",
            why="masking it would also mask ordinary text in the output",
        )
    env = dict(os.environ)
    for name, secret in env_secrets.items():
        if b"\0" in secret.reveal_bytes():
            raise UsageError(
                "a secret containing a NUL byte cannot go into an environment variable",
                fix="use --stdin REF instead",
            )
        env[name] = os.fsdecode(secret.reveal_bytes())  # byte-exact, even for non-UTF-8 values
    env.pop("KEYCHAIN_CALLER", None)  # the child is not us; it must declare its own caller

    if not redact and stdin_secret is None:
        try:
            os.execvpe(argv[0], argv, env)
        except FileNotFoundError as exc:
            raise MissingDependency(f"command not found: {argv[0]}") from exc
        except PermissionError as exc:
            raise UsageError(f"command not executable: {argv[0]}") from exc

    try:
        proc = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.PIPE if stdin_secret is not None else None,
            stdout=subprocess.PIPE if redact else None,
            stderr=subprocess.PIPE if redact else None,
        )
    except FileNotFoundError as exc:
        raise MissingDependency(f"command not found: {argv[0]}") from exc
    except PermissionError as exc:
        raise UsageError(f"command not executable: {argv[0]}") from exc
    del env

    def forward(signum: int, _frame: object) -> None:
        try:
            proc.send_signal(signum)
        except ProcessLookupError:
            pass

    previous = {s: signal.signal(s, forward) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    threads = []
    try:
        if redact:
            needles = [v for s in secrets for v in variants(s.reveal_bytes())]
            for src, dst in ((proc.stdout, sys.stdout.buffer), (proc.stderr, sys.stderr.buffer)):
                t = threading.Thread(target=_pump, args=(src, dst, Redactor(needles)), daemon=True)
                t.start()
                threads.append(t)
        if stdin_secret is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_secret.reveal_bytes())
                proc.stdin.close()
            except BrokenPipeError:
                pass
        rc = proc.wait()
        # A background grandchild can keep the pipes open long after the child exited; do not
        # wait for it. Output it writes after this point is dropped, never printed unmasked.
        for t in threads:
            t.join(timeout=2.0)
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    return 128 - rc if rc < 0 else rc
