"""`keychain install-skill`: advertise the tool to agent harnesses, the way sibling rig CLIs do.

Writes ``~/.agents/skills/keychain/SKILL.md`` (the Agent Skills location every harness scans),
the one-line ``~/.agents/skills/.blurbs/keychain.md`` that the machine's SessionStart
aggregator hook cats into new sessions, and a ``~/.claude/skills/keychain`` symlink when Claude
Code's skills dir exists. Idempotent: current files are left alone, a foreign link or dir is
never clobbered.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .errors import EXIT_USAGE

SKILL_NAME = "keychain"
# Any copy of our skill mentions the project; a same-named skill of another tool does not.
REPO_MARK = "keychain-cli"
BLURB = (
    "- `keychain` — secrets from the OS keychain (keychain-cli). Never read or print a "
    "credential: inject it with `keychain exec --env NAME=service/account -- cmd`, type a "
    "website password with `keychain fill REF --cdp URL --selector CSS`; "
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
    skill = skills / SKILL_NAME / "SKILL.md"
    try:
        foreign = skill.is_file() and REPO_MARK not in skill.read_text(encoding="utf-8", errors="replace")
        if foreign:
            print(
                f"keychain: {skill} belongs to another skill named `{SKILL_NAME}`; not overwritten "
                "(move it away and rerun `keychain install-skill`)",
                file=sys.stderr,
            )
            return EXIT_USAGE
        _write_if_changed(skill, skill_text())
    except OSError as exc:  # e.g. a file where the skill directory should be
        print(f"keychain: cannot write {skill} ({exc.strerror or type(exc).__name__})", file=sys.stderr)
        return EXIT_USAGE
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
