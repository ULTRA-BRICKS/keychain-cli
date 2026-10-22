"""Version tracks pyproject; install-skill writes the skill; the package imports stdlib only."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import keychainlib
from keychainlib import cli
from keychainlib.install import BLURB, skill_text

ROOT = Path(__file__).resolve().parent.parent


def test_version_matches_pyproject(capsys):
    declared = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)[1]
    assert keychainlib.__version__ == declared
    try:
        cli.main(["--version"])
    except SystemExit:
        pass
    assert capsys.readouterr().out.strip() == f"keychain {declared}"


def test_install_skill(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".claude" / "skills").mkdir(parents=True)
    assert cli.main(["install-skill"]) == 0
    skill = tmp_path / ".agents" / "skills" / "keychain" / "SKILL.md"
    assert skill.read_text() == skill_text()
    assert (tmp_path / ".agents" / "skills" / ".blurbs" / "keychain.md").read_text() == BLURB
    assert (tmp_path / ".claude" / "skills" / "keychain").resolve() == skill.parent
    assert cli.main(["install-skill"]) == 0
    assert "already current" in capsys.readouterr().out


def test_imports_are_stdlib_only():
    code = (
        "import sys, keychainlib.cli, keychainlib.backends.secretservice, "
        "keychainlib.backends.macos, keychainlib.execution, keychainlib.doctor, "
        "keychainlib.browser, keychainlib.cdp; "
        "mods = {m.split('.')[0] for m in sys.modules}; "
        "extra = mods - set(sys.stdlib_module_names) - {'keychainlib', '__main__', "
        "'sitecustomize', 'usercustomize'}; "
        "print(sorted(extra))"
    )
    out = subprocess.run(
        # -S: no site hooks, so a virtualenv's own helper modules are not counted as ours
        [sys.executable, "-S", "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert out == "[]"


def test_install_skill_leaves_a_foreign_skill_alone(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    foreign = tmp_path / ".agents" / "skills" / "keychain" / "SKILL.md"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("---\nname: keychain\ndescription: the ssh-agent manager\n---\n")
    assert cli.main(["install-skill"]) == 2
    assert "another skill" in capsys.readouterr().err
    assert "ssh-agent" in foreign.read_text()


def test_install_skill_reports_a_file_in_the_way(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".agents" / "skills").mkdir(parents=True)
    (tmp_path / ".agents" / "skills" / "keychain").write_text("not a directory")
    assert cli.main(["install-skill"]) == 2
    assert "cannot write" in capsys.readouterr().err
