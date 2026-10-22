# keychain-cli

`keychain` gives rig utilities and agents their tokens and passwords from the operating
system's secret store: the macOS Keychain, or the Secret Service on Linux (GNOME Keyring,
KWallet, KeePassXC). It replaces `.env` files, YAML configs and plaintext token files.

- Values go in only through stdin or a hidden prompt, never as command-line arguments.
- `keychain exec` hands a secret to a command without printing it, and masks it in the
  command's output.
- `keychain fill` types a website password into a browser field over the DevTools protocol,
  only on the site the password belongs to; `keychain capture` stores a field's value.
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

## Browser: fill and capture

A credential bound to a website can be typed into a Chromium page an agent drives, without the
value passing through the agent:

```sh
keychain set github/alex --origin https://github.com          # once, by you (hidden prompt)
keychain fill github/alex --cdp http://127.0.0.1:9222 --selector 'input[type=password]' \
  --caller browser-assist                                     # -> {"filled":true,...}
keychain capture github/new-token --cdp ws://127.0.0.1:9222/devtools/browser/ID \
  --selector '#token' --caller github                         # page field -> keychain
```

Filling needs your grant for the caller, the site and the credential (whoever drives the browser
can read a filled field back, so filling is reading):

```toml
[callers.browser-assist]
read = ["github/alex"]
fill = ["https://github.com", "https://*.example.com"]
```

The page (and every frame around the field) must be https on the credential's own host or on
a subdomain your grant names; the field must be a visible `type=password` input (or a
username/email field with `--field username`; a ref holds one value, so the login name is its
own ref, e.g. `github/alex-user`). From Python:
`Keychain("tool").fill(ref, cdp_url_or_playwright_cdp_session, selector)`.

Every fill by an agent or a utility (anyone but you at a terminal) is first confirmed by you.
keychain runs an approval command with the question as its argument and fills only on exit 0;
the default is `tg-ctl ask` (a Telegram question), and any other component can take its place:

```toml
approval_cmd = "tg-ctl ask"   # or any command: argv <cmd> <prompt>, env KEYCHAIN_APPROVAL_TIMEOUT
approval_timeout = 300

[callers.browser-assist]
approve = false               # optional: this caller is trusted, do not ask
```

See SPEC "Browser → Approval".

## Headless machines (SSH, cron, systemd)

A locked keyring never pops up a dialog nobody can see; the command fails with exit code 9.
Unlock it from an interactive SSH session with `keychain unlock`. On a server with no keyring
yet, start with `keychain unlock --create`. `keychain doctor` lists the steps.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | internal error |
| 2 | invalid arguments or malformed policy; `fill`: no (or more than one) matching field |
| 4 | no such secret |
| 5 | no secret store reachable; `fill`: no browser at the DevTools endpoint |
| 8 | denied: policy, a dialog; `fill`: wrong origin, not a password field, invalid TLS |
| 9 | the keyring is locked |
| 127 | a required system tool is missing |

## Develop

```sh
python3 -m pytest -q                                  # fake backend, fake `security`, D-Bus
KEYCHAIN_LIVE=1 python3 -m pytest -q -m live          # real gnome-keyring, throwaway collection
KEYCHAIN_INTEGRATION=1 python3 -m pytest -q -rs tests/integration   # + real Chromium (fill)
ruff check .
```

The integration suite runs the real binary against a throwaway gnome-keyring collection, real
consumers (curl, a second Python utility, a pseudo-terminal unlock) and headless Chromium on a
local self-signed https login page (`KEYCHAIN_FILL_TEST=1` allows loopback test pages). CI runs
it under `dbus-run-session` with Playwright's Chromium.

The macOS backend runs in tests against a fake `security` that follows Apple's sources. It
has not been run on a real Mac by CI, because there is no macOS runner.

License: MIT.
