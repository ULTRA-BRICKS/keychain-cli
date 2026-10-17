"""Append-only access journal: who touched which ref, when, with what outcome — never a value.

One JSON object per line in ``$XDG_STATE_HOME/keychain-cli/audit.jsonl`` (dir 0700, file
0600). A journal that cannot be written warns on stderr and does not block the operation: the
secret store, not this file, is the source of truth, and an unwritable disk must not lock the
user out of their own credentials.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def audit_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "keychain-cli" / "audit.jsonl"


def _parent_name(ppid: int) -> str:
    try:
        with open(f"/proc/{ppid}/comm", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


class Audit:
    def __init__(self, path: Path | None = None, enabled: bool = True) -> None:
        self.path = path or audit_path()
        self.enabled = enabled

    def record(self, op: str, ref: str, caller: str, outcome: str, *, agent: bool,
               backend: str, extra: dict | None = None) -> None:
        if not self.enabled:
            return
        ppid = os.getppid()
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "op": op, "ref": ref,
                 "caller": caller, "outcome": outcome, "agent": agent, "backend": backend,
                 "pid": os.getpid(), "ppid": ppid, "parent": _parent_name(ppid)}
        if extra:
            entry.update(extra)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as exc:
            print(f"keychain: warning: audit journal not written ({exc.strerror})",
                  file=sys.stderr)

    def tail(self, n: int) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out
