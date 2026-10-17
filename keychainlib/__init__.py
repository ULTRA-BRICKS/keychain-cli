"""keychain-cli — secrets for rig utilities from the OS keychain.

Stdlib-only. Public API: `Keychain`, `Secret`, the error classes in `keychainlib.errors`.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path

_DISTRIBUTION = "hyper-keychain"


def _version_from_pyproject() -> str:
    """The `[project] version` of the checkout this module runs from (symlink installs)."""
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    table = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', table.group(1) if table else text,
                      re.MULTILINE)
    return match.group(1) if match else "0+unknown"


def _resolve_version() -> str:
    try:
        return _version_from_pyproject()
    except OSError:
        pass
    try:
        return _pkg_version(_DISTRIBUTION)
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _resolve_version()

from .api import Keychain
from .secret import Secret

__all__ = ["Keychain", "Secret", "__version__"]
