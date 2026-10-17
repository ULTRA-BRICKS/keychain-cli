---
name: keychain
description: >-
  Secrets (tokens, passwords, API keys) for rig utilities and agents from the OS keychain
  (macOS Keychain, Linux Secret Service). Use whenever a command needs a credential: inject it
  with `keychain exec --env NAME=service/account -- cmd` instead of reading, printing, pasting or
  writing the value. Never put a secret into argv, a file, a log, git or a chat.
metadata:
  author: alex-mextner
  repo: https://git.hyperide.ai/ultrabricks/keychain-cli
---

# keychain — secrets without seeing them

Secrets live in the OS keychain under `service/account` refs (`tg-cli/bot-token`,
`3d-cli/thingiverse`). As an agent you **use** secrets, you do not **read** them: a value you
print lands in your context window, transcript and logs.

## Use a secret (the agent path)

```
keychain exec --env GITHUB_TOKEN=gh/default -- gh api user
keychain exec --env API_KEY=3d-cli/printops --caller 3d-cli -- 3d printops sync
keychain exec --stdin db/admin -- psql-wrapper --password-stdin
```

The child gets the value; its stdout/stderr are masked (`***`) by default. `--no-redact` only
for interactive programs whose output you will not read.

## Discover (metadata only, never values)

```
keychain list [service]          # refs, labels, notes
keychain info service/account
keychain exists service/account  # exit 0 yes, 4 no
keychain system list --match github   # website/Wi-Fi/app passwords other apps stored
keychain doctor                  # store, lock state, headless hints
keychain audit -n 20             # who accessed what (no values)
```

## Store a secret (values come from stdin or a hidden prompt — never argv)

Ask the human to run it in their own terminal: `keychain set service/account --label "..."`
(hidden prompt). A utility pipes it: `printf %s "$value" | keychain set --caller tool tool/name`.
Never ask the user to paste a secret into the chat.

## Rules

- Inside an agent session nothing prints a value: `get --reveal` and `exec --no-redact` are
  refused unless the **human** granted `reveal = true` to that caller. Do not try to work
  around this (another `--caller` name, editing the policy file, reading keyring files,
  `printenv` in a child). If you truly need a value shown, ask the human.
- A utility passes `--caller <its name>` (or `KEYCHAIN_CALLER`) and owns `<its name>/*`.
  Cross-namespace access needs a grant the **human** adds to
  `~/.config/keychain-cli/policy.toml`. Utilities that run under agents should consume their
  secrets through `keychain exec` (or the Python library), not `get --reveal`.
- Exit codes: 0 ok, 2 usage, 4 not found, 5 no store, 8 denied, 9 locked (`keychain unlock`
  in an interactive terminal — headless SSH, cron and systemd never show a prompt), 127 missing tool.
- Python utilities can import the library instead: `Keychain(caller="tool").get(ref)` returns
  a `Secret` that prints as `Secret(***)`; call `.reveal()` only where the value leaves.
