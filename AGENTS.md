# AGENTS.md — keychain-cli

Rules for agents working in this repo. English only in repo files. `SPEC.md` is the design and
security model; read it before changing behavior.

## What this is

`keychain` is the secret-store interface for the rig utilities: a stdlib-only Python CLI and
library over the macOS Keychain (`/usr/bin/security`) and the Linux Secret Service (a
hand-rolled D-Bus client). It is a sibling of tg-cli, review-cli, rig-cli and task-cli. Like
them, it installs as a symlink from `~/.local/bin/keychain` to `bin/keychain` in a clone, so
the main checkout is the deployed tool. Do the work in worktrees.

## Hard rules

- **A secret value never reaches argv, a log line, an exception message, stdout without
  `--reveal`, a file, or a test fixture committed to git.** Messages name refs. A last-resort
  error prints only the exception type. Add a test whenever you add an output path.
- **Stdlib only.** No runtime dependencies (`tests/test_meta.py` enforces it). The D-Bus
  client exists precisely so we need neither `secret-tool`, `busctl`/`gdbus` (which put the
  value in argv) nor a third-party package.
- **No file backend.** The fake backend is in-memory and cannot be selected from the CLI or
  the environment.
- **Policy is decided before the store is touched.** A denied call must not unlock anything,
  prompt or read.
- **Never weaken the agent rules quietly.** These rules are: `get --reveal` is refused for
  `agent` and `user` inside an agent session; an agent session cannot claim `user`; `exec`
  redacts by default; `KEYCHAIN_CALLER` is not passed on to children. If one of them has to
  change, change `policy.py` and the tests, and record why in the CHANGELOG.
- **Headless never hangs.** With no display or with `--no-prompt`, a locked store raises
  `Locked` (exit 9) and dismisses the prompt.
- Live tests (`KEYCHAIN_LIVE=1`) create and delete their own collection; never write to the
  user's login keyring in a test.

## Layout

```
bin/keychain                  symlink-install shim
keychainlib/cli.py            argparse front end (thin)
keychainlib/api.py            Keychain: policy + audit around a backend
keychainlib/policy.py         callers, namespaces, grants, reveal rules
keychainlib/context.py        caller resolution, agent-session detection
keychainlib/execution.py      exec: env/stdin injection, streaming redaction
keychainlib/audit.py          value-free JSONL journal
keychainlib/backends/         secretservice.py (+ dbus.py), macos.py, fake.py
keychainlib/SKILL.md          the agent skill `keychain install-skill` writes
```

## Release

Bump `[project] version` in `pyproject.toml` (`keychain --version` reads it) and add a
CHANGELOG entry. Ship through a PR and `gh ship`. Afterwards run `git pull` in the main clone
on each machine, then `keychain install-skill` if `SKILL.md` changed.

## Verify

`python3 -m pytest -q`, `KEYCHAIN_LIVE=1 python3 -m pytest -q -m live` on a Linux desktop,
`ruff check .`.
