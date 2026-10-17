"""`keychain doctor`: what store is in use, is it reachable and unlocked, and what to do if not."""

from __future__ import annotations

import os
import platform
import sys

from . import __version__
from .audit import audit_path
from .errors import KeychainError
from .policy import policy_path

HEADLESS_LINUX = [
    "sudo apt install gnome-keyring dbus-user-session libpam-gnome-keyring",
    "systemctl --user enable --now gnome-keyring-daemon.socket   # starts on first use",
    "keychain unlock --create   # once per machine: creates the default keyring",
    "keychain unlock            # after each reboot, from an interactive SSH session",
    (
        "loginctl enable-linger $USER   # keep the user bus (and the unlocked keyring) alive "
        "for cron/systemd jobs between logins"
    ),
]


def diagnose(kc) -> dict:
    report: dict = {
        "version": __version__,
        "platform": f"{sys.platform} {platform.release()}",
        "caller": kc.caller,
        "agent_session": kc.agent,
        "ssh": bool(os.environ.get("SSH_CONNECTION")),
        "policy": str(policy_path()),
        "policy_present": policy_path().exists(),
        "audit": str(audit_path()),
    }
    hints: list[str] = []
    try:
        status = kc.backend.status()
    except KeychainError as exc:
        status = {"error": exc.what, "fix": exc.fix}
    report["store"] = status
    ok = "error" not in status
    if sys.platform.startswith("linux"):
        ok = ok and status.get("service", False) and status.get("default") is not None
        default = next((c for c in status.get("collections", []) if c.get("default")), None)
        if not status.get("bus_reachable", True) or not status.get("service", True):
            hints += HEADLESS_LINUX
        elif status.get("default") is None:
            hints.append("no default keyring: `keychain unlock --create`")
        elif default and default.get("locked"):
            hints.append(
                "the default keyring is locked: `keychain unlock` (TTY password) — "
                "agents and cron jobs get exit 9 until then"
            )
        if not status.get("display") and ok:
            hints.append(
                "no graphical session: unlock prompts cannot appear here; a locked "
                "keyring fails fast (exit 9) instead of hanging"
            )
    report["ok"] = bool(ok)
    report["hints"] = hints
    return report


def render(report: dict) -> str:
    lines = [
        f"keychain {report['version']} on {report['platform']}",
        (f"caller: {report['caller']}   agent session: {report['agent_session']}   ssh: {report['ssh']}"),
    ]
    store = report["store"]
    lines.append(f"store: {store.get('backend', '?')}")
    for key in ("provider", "bus", "default", "keychain", "security"):
        if store.get(key):
            lines.append(f"  {key}: {store[key]}")
    for c in store.get("collections", []):
        flags = ", ".join(f for f, on in (("default", c["default"]), ("locked", c["locked"])) if on)
        lines.append(f"  collection {c['id']} ({c['label'] or 'unnamed'}){f' [{flags}]' if flags else ''}")
    if store.get("info"):
        lines.append(f"  {store['info']}")
    if store.get("error"):
        lines.append(f"  error: {store['error']}")
    lines.append(
        f"policy: {report['policy']} ({'present' if report['policy_present'] else 'absent: built-in rules'})"
    )
    lines.append(f"audit:  {report['audit']}")
    lines.append("status: " + ("OK" if report["ok"] else "NOT READY"))
    for h in report["hints"]:
        lines.append(f"  - {h}")
    return "\n".join(lines)
