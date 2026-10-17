"""Who is calling: the declared caller and whether an LLM agent harness is in the process tree.

Agent detection reads environment markers the harnesses export to every child process. It is a
guard against accidents (an agent pasting a secret into its own transcript), not a security
boundary: a same-user process can unset the variables. ``KEYCHAIN_AGENT=1`` forces agent mode
(for harnesses we do not recognise); there is deliberately no switch that turns a detected
harness back into a human session.
"""

from __future__ import annotations

import os

from .errors import UsageError
from .refs import valid_service

AGENT_MARKERS = (
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "OMPCODE",
    "OPENCODE",
    "GEMINI_CLI",
    "CURSOR_AGENT",
    "PI_CODING_AGENT",
)
AGENT_PREFIXES = ("CODEX_",)
USER = "user"
AGENT = "agent"


def harness_detected(environ: dict[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return any(env.get(name) for name in AGENT_MARKERS) or any(
        k.startswith(AGENT_PREFIXES) and v for k, v in env.items()
    )


def in_agent_context(environ: dict[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get("KEYCHAIN_AGENT") == "1" or harness_detected(env)


def resolve_caller(flag: str | None, environ: dict[str, str] | None = None) -> str:
    """``--caller`` > ``KEYCHAIN_CALLER`` > ``agent`` (inside a harness) or ``user``."""
    env = os.environ if environ is None else environ
    name = flag or env.get("KEYCHAIN_CALLER") or (AGENT if in_agent_context(env) else USER)
    if not valid_service(name):
        raise UsageError(
            f"invalid caller name {name!r}", fix="a caller is the utility's name, e.g. --caller tg-cli"
        )
    if name == USER and in_agent_context(env):
        raise UsageError(
            "an agent session cannot act as the human `user` caller",
            why="`user` has unrestricted access; inside an agent harness the default caller is `agent`",
            fix="pass your utility's name: --caller <tool>",
        )
    return name
