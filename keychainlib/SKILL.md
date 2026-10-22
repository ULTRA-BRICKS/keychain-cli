---
name: keychain
description: >-
  Secrets (tokens, passwords, API keys) for rig utilities and agents from the OS keychain
  (macOS Keychain, Linux Secret Service). Use whenever a command needs a credential: inject it
  with `keychain exec --env NAME=service/account -- cmd` instead of reading, printing, pasting or
  writing the value; type a website password into a browser with `keychain fill`. Never put a
  secret into argv, a file, a log, git or a chat.
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

## Log in to the user's account in a browser

A task needs a website login. Drive the browser through the `browser-assist` skill if it is
installed (it adds Telegram confirmations, captcha/2FA handoff and `fill-secret`, which calls
`keychain fill`); the steps below are what happens underneath and what to do with a bare
`agent-browser`.

1. **Find the credential by site** (metadata only): `keychain list`, `keychain info REF`
   (shows `origin:`), `keychain system list --match site.tld`. A ref holds ONE value, so a login
   is two refs: `site/user` (the login name) and `site/password`. Nothing there → ask the human
   (Telegram, `browser-assist handoff` or `tg --tag decision`; write the message in Russian):
   "a login on site.tld is needed, store it: `keychain set site/user --origin https://site.tld`
   and `keychain set site/password --origin https://site.tld`". Never ask for the password itself.
2. **Open the login page** in the agent's own browser profile and get its DevTools endpoint:
   `agent-browser get cdp-url` (`ws://127.0.0.1:…/devtools/browser/…`). Loopback only.
3. **Fill**, then submit (submitting is a significant action: confirm it with the human when
   browser-assist is in use):

   ```
   keychain fill site/user --cdp "$CDP" --selector 'input[autocomplete=username]' --field username --caller TOOL
   keychain fill site/password --cdp "$CDP" --selector 'input[type=password]' --caller TOOL
   keychain fill site/password --cdp "$CDP" --focused --target TAB_ID --caller TOOL   # the focused field
   ```

   stdout is only `{"filled":true,"selector":…,"origin":…}`. The value goes store → browser
   inside the keychain process. It is typed only into an https page whose origin is the
   credential's own (or a subdomain the human allowed), into a visible `type=password` field
   (or a username/email field), and every frame around the field must pass too.

   **The human confirms every fill.** Before the value is fetched, keychain asks the human through
   the approval command (default `tg-ctl ask`: a Telegram question with Approve/Decline
   buttons that names you, the ref and the site, never a value). The call blocks until he
   answers (up to `approval_timeout`, 300 s by default). exit 8 `did not approve` = declined,
   timed out or the approver failed: stop and report; do not loop. Do not message the human a
   second question yourself. The command is replaceable (`approval_cmd` in the policy file;
   contract: argv `<cmd> <prompt>`, env `KEYCHAIN_APPROVAL_TIMEOUT`, exit 0 = approved), and
   the human may exempt a caller with `approve = false`. You cannot change either, and
   `KEYCHAIN_APPROVAL_CMD` is ignored inside agent sessions.
4. **2FA, captcha, e-mail or device confirmation: never bypass.** Hand the step to the human
   and wait: `browser-assist handoff --reason '…'` (screenshot + live view) or `ask-code FIELD`
   (the human sends the code, the tool types it; you get only `{"status":"filled"}`). Without
   browser-assist: `tg --tag decision --photo shot.png "<in Russian: site.tld asks for the SMS
   code; enter it in the agent's browser yourself>"`. Never repeat a code in your transcript,
   never solve a captcha. `keychain fill` types only passwords and usernames, not one-time codes.
5. **The session lives in the browser profile** (its directory). Do not export, print or copy
   cookies or local storage.
6. **exit 8 "may not fill credentials into https://site.tld"** → hand the human the exact line
   from the error's `fix:` (`[callers.TOOL] fill = ["https://site.tld"]` in
   `~/.config/keychain-cli/policy.toml`). Never edit the policy file yourself. Other exit 8s
   (wrong origin, iframe from another site, not a password field, invalid TLS) mean the page is
   not the one the credential belongs to: stop and report, do not look for another selector.

A new token shown on a page goes into the store, not into your context:
`keychain capture site/api-token --cdp "$CDP" --selector '#token' --caller site` stores the
field's value bound to the page's origin and prints only `{"captured":true,…}`.

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
