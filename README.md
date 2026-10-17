# keychain-cli

`keychain` gives rig utilities and agents their tokens and passwords from the operating
system's secret store: the macOS Keychain, or the Secret Service on Linux (GNOME Keyring,
KWallet, KeePassXC). It replaces `.env` files, YAML configs and plaintext token files.

- Values go in only through stdin or a hidden prompt, never as command-line arguments.
- `keychain exec` hands a secret to a command without printing it, and masks it in the
  command's output.
- A policy decides which utility may read which secrets. Every access is journaled, without
  values.
- Agents use secrets but do not see them. Inside an agent session, printing a value is refused.
- Python 3.11+, standard library only. Linux talks D-Bus directly; macOS uses `/usr/bin/security`.

Design and security model: [`SPEC.md`](SPEC.md).

## Install

```sh
curl -fsSL https://git.hyperide.ai/ultrabricks/keychain-cli/raw/branch/main/install.sh | bash
# or, from a clone:  ./install.sh
keychain doctor
```

The installer symlinks `~/.local/bin/keychain` to the clone and registers the agent skill. If
another `keychain` is already on your PATH (the ssh-agent manager of the same name), it stops
and tells you why.

## Use

```sh
keychain set tg-cli/bot-token --label "Telegram bot"      # hidden prompt
printf %s "$TOKEN" | keychain set tg-cli/bot-token        # or from a pipe
keychain exec --env TG_BOT_TOKEN=tg-cli/bot-token -- tg send "hi"
keychain list                                             # refs and labels, never values
keychain get tg-cli/bot-token --reveal                    # print it (needs --reveal)
keychain system list --match github                       # passwords other apps stored
keychain audit                                            # who read what, and when
```

A utility declares who is asking with `--caller`, and the best path is to have the value
injected rather than read:

```sh
keychain exec --caller tg-cli --env TG_BOT_TOKEN=tg-cli/bot-token -- tg-daemon
```

In Python, with the package importable:

```python
from keychainlib import Keychain
token = Keychain(caller="tg-cli").get("tg-cli/bot-token")   # prints as Secret(***)
use(token.reveal())
```

A utility owns its own namespace (`tg-cli/*`). Access to another namespace, to system items,
or printing values from inside an agent session (`get --reveal`, `exec --no-redact`) needs
an entry in `~/.config/keychain-cli/policy.toml`, which only you edit:

```toml
[callers.marketplace]
read = ["3d-cli/printops", "system:iCloud_5fPasswords/*"]

[callers.tg-cli]
reveal = true   # tg reads its token with `keychain get --reveal` even when an agent runs tg
```

## Headless machines (SSH, cron, systemd)

A locked keyring never pops up a dialog nobody can see; the command fails with exit code 9.
Unlock it from an interactive SSH session with `keychain unlock`. On a server with no keyring
yet, start with `keychain unlock --create`. `keychain doctor` lists the steps.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | internal error |
| 2 | invalid arguments or malformed policy |
| 4 | no such secret |
| 5 | no secret store reachable |
| 8 | denied by policy or by a dialog |
| 9 | the keyring is locked |
| 127 | a required system tool is missing |

## Develop

```sh
python3 -m pytest -q                                  # fake backend, fake `security`, D-Bus
KEYCHAIN_LIVE=1 python3 -m pytest -q -m live          # real gnome-keyring, throwaway collection
ruff check .
```

The macOS backend runs in tests against a fake `security` that follows Apple's sources. It
has not been run on a real Mac by CI, because there is no macOS runner.

License: MIT.
