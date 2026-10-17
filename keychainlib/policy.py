"""Access policy: which caller may touch which secrets.

Rules, in order:

1. ``user`` (a human outside any agent harness) may do everything.
2. Every other caller owns its namespace: ``tg-cli`` may read and write ``tg-cli/*``.
3. Anything else needs a grant in ``$XDG_CONFIG_HOME/keychain-cli/policy.toml``::

       [callers.marketplace]
       read = ["3d-cli/printops", "3d-cli/thingiverse"]   # globs over refs
       write = []
       reveal = true   # may print values / exec --no-redact inside an agent session

   System items (``system:<id>``) are never owned; reading one needs a grant whose pattern
   starts with ``system:``, such as ``read = ["system:login/*"]``.
4. Inside an agent session, a value may be printed (`get --reveal`) or handed to an
   unredacted child (`exec --no-redact`) only by a caller whose entry says ``reveal = true``;
   never by ``agent`` or ``user``. Claiming a utility's name is easy for an agent, so owning a
   namespace is not enough. Redacted `exec` is the path for agents: the value goes to the
   child process, never into the transcript.

The policy file is the user's: keychain-cli reads it and never writes it.
"""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .context import AGENT, USER
from .errors import PolicyDenied, UsageError
from .refs import SYSTEM_PREFIX, Ref, SystemRef

READ, WRITE = "read", "write"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "keychain-cli"


def policy_path() -> Path:
    return config_dir() / "policy.toml"


@dataclass(frozen=True)
class Grant:
    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    reveal: bool | None = None


@dataclass
class Policy:
    callers: dict[str, Grant] = field(default_factory=dict)
    source: str = "(built-in defaults)"

    @classmethod
    def load(cls, path: Path | None = None) -> Policy:
        path = path or policy_path()
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return cls()
        except OSError as exc:
            raise UsageError(f"cannot read the policy file {path}", why=str(exc)) from exc
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise UsageError(f"malformed policy file {path}", why=str(exc)) from exc
        return cls.from_dict(data, str(path))

    @classmethod
    def from_dict(cls, data: dict, source: str = "(inline)") -> Policy:
        unknown = set(data) - {"callers"}
        if unknown:
            raise UsageError(
                f"unknown policy keys: {', '.join(sorted(unknown))}",
                fix="the policy has one table: [callers.<name>]",
            )
        callers = {}
        callers_table = data.get("callers") or {}
        if not isinstance(callers_table, dict):
            raise UsageError("policy key `callers` must be a table of [callers.<name>] entries")
        for name, entry in callers_table.items():
            if not isinstance(entry, dict) or set(entry) - {"read", "write", "reveal"}:
                raise UsageError(f"policy entry callers.{name} must have only read/write/reveal")
            for key in ("read", "write"):
                value = entry.get(key, [])
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise UsageError(f"callers.{name}.{key} must be a list of ref globs")
            reveal = entry.get("reveal")
            if reveal is not None and not isinstance(reveal, bool):
                raise UsageError(f"callers.{name}.reveal must be true or false")
            callers[name] = Grant(tuple(entry.get("read", [])), tuple(entry.get("write", [])), reveal)
        return cls(callers, source)

    def allows(self, caller: str, op: str, ref: Ref | SystemRef) -> bool:
        if caller == USER:
            return True
        if isinstance(ref, Ref) and ref.service == caller:
            return True
        grant = self.callers.get(caller)
        if grant is None:
            return False
        patterns = grant.read if op == READ else grant.write
        system = isinstance(ref, SystemRef)
        # A system ref matches only patterns that say `system:`; `*` alone never grants
        # every website and Wi-Fi password.
        return any(
            fnmatch.fnmatchcase(str(ref), p) for p in patterns if p.startswith(SYSTEM_PREFIX) == system
        )

    def check(self, caller: str, op: str, ref: Ref | SystemRef) -> None:
        if not self.allows(caller, op, ref):
            raise PolicyDenied(
                f"caller `{caller}` may not {op} {ref}",
                why=f"a caller owns only its own namespace ({caller}/*); other refs need a "
                f"grant in {self.source}",
                fix=f'ask the user to add under [callers.{caller}] {op} = ["{ref}"] in '
                f"{policy_path()} (agents must not edit it)",
            )

    def may_reveal(self, caller: str, agent: bool) -> bool:
        """May the value be printed (or exec'd unredacted)? Outside agent sessions: yes. Inside
        one: only for a caller the human granted ``reveal = true``; never `agent` or `user`."""
        if not agent:
            return True
        if caller in (USER, AGENT):
            return False
        grant = self.callers.get(caller)
        return grant is not None and grant.reveal is True
