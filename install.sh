#!/usr/bin/env bash
# install.sh — install the `keychain` CLI (keychain-cli, Python 3.11+, stdlib only).
# From a clone (./install.sh) or piped:
#   curl -fsSL https://git.hyperide.ai/ultrabricks/keychain-cli/raw/branch/main/install.sh | bash
# The install is a symlink ~/.local/bin/keychain -> <clone>/bin/keychain, like the other rig
# CLIs: updating is `git pull` in the clone (main checked out = the deployed tool).
set -euo pipefail

TOOL="keychain"
REPO="keychain-cli"
FORGE="https://git.hyperide.ai/ultrabricks"
ENTRY="bin/keychain"
CLONE_BASE="${XDG_DATA_HOME:-$HOME/.local/share}"
EXPECT_URL="$FORGE/$REPO.git"
BIN="$HOME/.local/bin"

case "$(uname -s)" in
  Linux|Darwin) ;;
  *) echo "ERROR: keychain supports macOS and Linux only (got $(uname -s))." >&2; exit 2 ;;
esac

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo "ERROR: keychain needs python3 >= 3.11 on PATH (found: $(python3 --version 2>&1 || echo none))." >&2
  echo "       macOS: brew install python   Ubuntu 22.04: sudo apt install python3.11" >&2
  exit 127
fi

# Compare the clone's origin as host + path, never as a substring (a look-alike host must not
# be pulled and installed as the tool that handles every secret).
_url_host_path() {
  local _u _hp _path _host
  _u=${1%/}; _u=${_u%.git}
  case "$_u" in
    https://*|ssh://*) _u=${_u#*://}; _hp=${_u%%/*}; _path=${_u#*/} ;;
    *@*:*) _hp=${_u%%:*}; _path=${_u#*:} ;;
    *) return 1 ;;
  esac
  [ "$_path" != "$_u" ] || return 1
  case "$_hp" in *[!A-Za-z0-9._:@%~-]*) return 1 ;; esac
  _host=${_hp##*@}; _host=${_host%%:*}
  printf '%s %s\n' "$_host" "$_path"
}

_script_dir=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" ]]; then
  _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -n "$_script_dir" && -f "$_script_dir/$ENTRY" ]]; then
  SRC="$_script_dir"
  echo "keychain: using local clone at $SRC"
else
  mkdir -p "$CLONE_BASE"
  CLONE_DIR="$CLONE_BASE/$REPO"
  if [[ -d "$CLONE_DIR/.git" ]]; then
    actual_url="$(git -C "$CLONE_DIR" remote get-url origin 2>/dev/null || echo "")"
    if [ "$(_url_host_path "$actual_url")" != "git.hyperide.ai ultrabricks/$REPO" ]; then
      echo "ERROR: $CLONE_DIR exists but its origin is '$actual_url', not $EXPECT_URL." >&2
      exit 1
    fi
    echo "keychain: updating $CLONE_DIR"
    git -C "$CLONE_DIR" pull --ff-only origin "$(git -C "$CLONE_DIR" symbolic-ref --quiet --short HEAD || echo HEAD)"
  else
    echo "keychain: cloning $EXPECT_URL into $CLONE_DIR"
    git clone "$EXPECT_URL" "$CLONE_DIR"
  fi
  SRC="$CLONE_DIR"
fi

ENTRY_PATH="$SRC/$ENTRY"
_canon() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }

# Another program called `keychain` (Funtoo's ssh-agent manager, Ubuntu package `keychain`) is
# often run from shell rc files as `eval $(keychain --eval ...)`. Shadowing it would break
# those shells, so refuse unless the user says so. Our own earlier install is recognised by
# where it resolves to (bin/keychain beside a keychainlib package), not by its content.
_ours() { local _r; _r="$(_canon "$1")"; [[ "$(basename "$_r")" == "keychain" && -f "$(dirname "$(dirname "$_r")")/keychainlib/__init__.py" ]]; }
_existing="$(command -v "$TOOL" 2>/dev/null || true)"
if [[ -n "$_existing" ]] && ! _ours "$_existing" && [[ "${KEYCHAIN_CLI_FORCE:-}" != "1" ]]; then
  echo "ERROR: another '$TOOL' is already on PATH: $_existing" >&2
  echo "       (probably the ssh-agent manager of the same name). Installing would shadow it." >&2
  echo "       Re-run with KEYCHAIN_CLI_FORCE=1 to install anyway, or remove the other one." >&2
  exit 1
fi

mkdir -p "$BIN"
chmod +x "$ENTRY_PATH"
ln -sfn "$ENTRY_PATH" "$BIN/$TOOL"
echo "keychain: symlinked $BIN/$TOOL -> $ENTRY_PATH"
if [[ ":$PATH:" != *":$BIN:"* ]]; then
  echo "  NOTE: $BIN is not on PATH; add: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

"$BIN/$TOOL" install-skill || echo "  WARNING: '$TOOL install-skill' failed; re-run it manually."

echo ""
echo "  keychain $("$BIN/$TOOL" --version | cut -d' ' -f2) is installed."
echo "  Check the store:   keychain doctor"
echo "  Store a secret:    keychain set service/account        (hidden prompt)"
echo "  Use it:            keychain exec --env NAME=service/account -- command"
