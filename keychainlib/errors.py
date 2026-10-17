"""Structured errors with stable exit codes (the agent-tools error contract, plus LOCKED=9).

Every message names refs (``service/account``), never a secret value: these strings reach
stderr, logs and agent transcripts.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_NOT_FOUND = 4  # agent-tools EXIT_UNKNOWN_ITEM
EXIT_UNAVAILABLE = 5  # agent-tools EXIT_MISSING_TARGET: no secret store reachable
EXIT_DENIED = 8  # agent-tools EXIT_PERMISSION: policy or the user refused access
EXIT_LOCKED = 9  # keychain-specific: the store is locked and could not be unlocked here
EXIT_MISSING_DEP = 127

EXIT_CODES = {
    EXIT_OK: "success",
    EXIT_INTERNAL: "internal error (a bug or an unexpected store reply)",
    EXIT_USAGE: "invalid arguments or malformed policy",
    EXIT_NOT_FOUND: "no such secret",
    EXIT_UNAVAILABLE: "no secret store reachable (Secret Service / Keychain)",
    EXIT_DENIED: "access denied (policy, or the user declined a prompt)",
    EXIT_LOCKED: "the keyring is locked; run `keychain unlock`",
    EXIT_MISSING_DEP: "a required system tool is missing",
}


class KeychainError(Exception):
    exit_code = EXIT_INTERNAL

    def __init__(self, what: str, why: str = "", fix: str = "") -> None:
        super().__init__(what)
        self.what = what
        self.why = why
        self.fix = fix

    def render(self) -> str:
        lines = [f"keychain: {self.what}"]
        if self.why:
            lines.append(f"  why: {self.why}")
        if self.fix:
            lines.append(f"  fix: {self.fix}")
        return "\n".join(lines)


class UsageError(KeychainError):
    exit_code = EXIT_USAGE


class NotFound(KeychainError):
    exit_code = EXIT_NOT_FOUND


class BackendUnavailable(KeychainError):
    exit_code = EXIT_UNAVAILABLE


class PolicyDenied(KeychainError):
    exit_code = EXIT_DENIED


class Locked(KeychainError):
    exit_code = EXIT_LOCKED


class MissingDependency(KeychainError):
    exit_code = EXIT_MISSING_DEP


class BackendError(KeychainError):
    exit_code = EXIT_INTERNAL
