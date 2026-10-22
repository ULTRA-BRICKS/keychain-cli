"""Human approval before a credential is typed into a page: a replaceable channel.

keychain-cli does not know how to reach a human. It runs a command, and the command does. The
default is tg-cli's blocking question (`tg-ctl ask`); any component that can put a question in
front of a person and report the answer by exit status can take its place.

Contract of the command (nothing here is specific to Telegram):

* argv is the configured command followed by one argument, the prompt text (a plain sentence
  naming the caller, the credential's ref, the page origin and the field kind; never a value);
* the environment is ours plus ``KEYCHAIN_APPROVAL_TIMEOUT`` (seconds the human has),
  ``KEYCHAIN_APPROVAL_CALLER``, ``KEYCHAIN_APPROVAL_REF`` and ``KEYCHAIN_APPROVAL_ORIGIN`` for
  a channel that wants them as data instead of parsing the sentence;
* stdin is empty, stdout and stderr are discarded;
* exit status 0 means approved. Anything else (a refusal, a timeout, a crash, being killed)
  means denied. We stop waiting after the timeout plus a short grace and treat it as denied.

Resolution of the command, first match wins:

1. ``approval_cmd`` in the policy file (a string split like a shell line without a shell, or a
   list of strings). The file is the human's.
2. ``KEYCHAIN_APPROVAL_CMD`` in the environment, outside agent sessions only: an agent that
   could set it would approve itself.
3. ``tg-ctl ask``.

A later resolver (rig providers) can slot in by supplying the command in step 1/2's place;
nothing else here changes.
"""

from __future__ import annotations

import os
import shlex
import subprocess

from .errors import MissingDependency, PolicyDenied, UsageError

DEFAULT_COMMAND = ("tg-ctl", "ask")
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 900
_GRACE = 15  # seconds past the human's timeout before we give up on the command itself
ENV_COMMAND = "KEYCHAIN_APPROVAL_CMD"


def parse_command(value: object, where: str) -> tuple[str, ...]:
    """A command from the policy file or the environment: a string or a list of strings."""
    if isinstance(value, str):
        try:
            argv = tuple(shlex.split(value))
        except ValueError as exc:
            raise UsageError(f"{where} is not a valid command line", why=str(exc)) from exc
    elif isinstance(value, list) and all(isinstance(v, str) for v in value):
        argv = tuple(value)
    else:
        raise UsageError(f"{where} must be a string or a list of strings")
    if not argv:
        raise UsageError(f"{where} is empty")
    return argv


def resolve_command(
    policy_command: tuple[str, ...] | None, *, agent: bool, environ: dict[str, str] | None = None
) -> tuple[tuple[str, ...], str]:
    """The approval command and where it came from (``policy``, ``env`` or ``default``)."""
    env = os.environ if environ is None else environ
    if policy_command:
        return policy_command, "policy"
    from_env = env.get(ENV_COMMAND)
    if from_env and not agent:
        return parse_command(from_env, ENV_COMMAND), "env"
    return DEFAULT_COMMAND, "default"


def request(
    command: tuple[str, ...],
    prompt: str,
    *,
    timeout: int,
    caller: str,
    ref: str,
    origin: str,
    environ: dict[str, str] | None = None,
) -> bool:
    """Run the approval command. True only for exit status 0 within the time limit."""
    argv = [*command, prompt]
    if tuple(command[:2]) == DEFAULT_COMMAND and not any(
        a == "--timeout" or a.startswith("--timeout=") for a in command
    ):
        # `tg-ctl ask [options]` takes its limit as a flag; before the prompt, so a trailing `--`
        # in the configured options cannot turn it into text. A --timeout the human wrote is not
        # doubled, but `approval_timeout` is still how long we wait: it cannot be extended here.
        argv = [*command[:2], "--timeout", str(timeout), *command[2:], prompt]
    env = dict(os.environ if environ is None else environ)
    env.pop("KEYCHAIN_CALLER", None)  # a child does not inherit its parent's identity (SPEC rule 4)
    env.update(
        KEYCHAIN_APPROVAL_TIMEOUT=str(timeout),
        KEYCHAIN_APPROVAL_CALLER=caller,
        KEYCHAIN_APPROVAL_REF=ref,
        KEYCHAIN_APPROVAL_ORIGIN=origin,
    )
    try:
        done = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=timeout + _GRACE,
            check=False,
        )
    except FileNotFoundError:
        raise MissingDependency(
            f"approval command `{command[0]}` not found",
            why="filling needs a human's approval and nothing could ask for it",
            fix="install it, or set `approval_cmd` in the policy file to a command that asks the "
            "human (exit 0 = approved)",
        ) from None
    except PermissionError:
        raise MissingDependency(f"approval command `{command[0]}` is not executable") from None
    except subprocess.TimeoutExpired:
        return False
    return done.returncode == 0


def require(
    *,
    command: tuple[str, ...],
    timeout: int,
    caller: str,
    ref: str,
    origin: str,
    field: str,
) -> None:
    """Ask the human; raise PolicyDenied unless they approved."""
    prompt = f"keychain: allow `{caller}` to type {ref} ({field}) into {origin}?"
    if not request(command, prompt, timeout=timeout, caller=caller, ref=ref, origin=origin):
        raise PolicyDenied(
            f"the human did not approve filling {ref} into {origin}",
            why="every fill by a non-`user` caller is confirmed by a person (declined, timed out "
            "or the approval command failed)",
            fix="ask again, or have the human grant `approve = false` for this caller in the policy file",
        )
