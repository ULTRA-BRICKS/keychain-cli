"""`keychain install-skill`: advertise the tool to agent harnesses, the way sibling rig CLIs do.

Writes ``~/.agents/skills/keychain/SKILL.md`` (the Agent Skills location every harness scans),
the one-line ``~/.agents/skills/.blurbs/keychain.md`` that the machine's SessionStart
aggregator hook cats into new sessions, and a ``~/.claude/skills/keychain`` symlink when Claude
Code's skills dir exists. Idempotent: current files are left alone, a foreign link or dir is
never clobbered.
"""

from __future__ import annotations

import os
from pathlib import Path

SKILL_NAME = "keychain"
BLURB = (
    "- `keychain` — secrets from the OS keychain (keychain-cli). Never read or print a "
    "credential: inject it with `keychain exec --env NAME=service/account -- cmd`; "
    "`keychain list` / `keychain system list` show metadata only; storing a value is the "
    "human's job (`keychain set ref`, hidden prompt).\n"
)


def skill_text() -> str:
    return (Path(__file__).parent / "SKILL.md").read_text(encoding="utf-8")


def _home() -> Path:
    return Path(os.environ.get("HOME") or os.path.expanduser("~"))


def _write_if_changed(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and target.read_text(encoding="utf-8") == content:
        print(f"keychain: already current at {target}")
        return
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, target)
    print(f"keychain: wrote {target}")


def install_skill() -> int:
    home = _home()
    skills = home / ".agents" / "skills"
    _write_if_changed(skills / SKILL_NAME / "SKILL.md", skill_text())
    _write_if_changed(skills / ".blurbs" / f"{SKILL_NAME}.md", BLURB)
    claude = home / ".claude" / "skills"
    link = claude / SKILL_NAME
    if claude.is_dir() and not (link.exists() or link.is_symlink()):
        try:
            link.symlink_to(skills / SKILL_NAME)
            print(f"keychain: linked {link}")
        except OSError:
            pass  # the ~/.agents copy is the one that matters
    return 0
