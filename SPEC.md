# keychain-cli — specification

One CLI (`keychain`) and one Python library (`keychainlib`) through which every rig utility and
agent gets its credentials from the operating system's secret store instead of `.env` files,
YAML configs and plaintext token files.

## Stores

| Platform | Store | Transport |
| --- | --- | --- |
| Linux | freedesktop Secret Service: GNOME Keyring, KWallet 6, KeePassXC | a stdlib D-Bus client on the session bus (`keychainlib/backends/dbus.py`) |
| macOS | the login keychain (or `--store <file>`) | `/usr/bin/security` |

There is no file backend. A store that keeps values on disk in the clear is what this tool replaces.

Why not `secret-tool`, `busctl`, `gdbus` or `keyring`: `busctl` and `gdbus` take the value as an
argument, so it shows up in `/proc/<pid>/cmdline`. `secret-tool search` prints every value it
finds. The `keyring` package would be a third-party dependency sitting in the path of every
secret. A D-Bus client of about 400 lines is small enough to review.

## Names

- A keychain-cli item is `service/account`. The service is the owning utility (`tg-cli`), the
  account is the credential's name (`bot-token`). The allowed characters are
  `[A-Za-z0-9._-]` for the service and `[A-Za-z0-9._@+:-]` for the account; neither may
  start with `.` or `-`.
- Linux: the item has the attributes `xdg:schema=ai.hyperide.keychain`, `service`, `account`
  and an optional `note`. It lives in the default collection, or in `--store` (a collection
  label or id).
- macOS: the item is a generic password with service `service`, account `account` and kind
  (`-D`) `keychain-cli`. The label and the note map to the keychain's label and comment.
- A system item is anything another app stored: website passwords (synced by passwords-app,
  stored by browsers), Wi-Fi passwords, app tokens. It is addressed as `system:<id>`, using
  the id that `keychain system list` prints. On Linux the id is `<collection>/<item>`, for
  example `login/12`. On macOS it is `inet:<server>/<account>` or `genp:<service>/<account>`,
  percent-encoded.

## Commands

```
keychain set REF [--label L] [--note N] [--raw]   value from stdin or a hidden TTY prompt
keychain get REF --reveal                         value to stdout (no newline unless a TTY)
keychain exec [--env NAME=REF]... [--stdin REF] [--no-redact] -- CMD...
keychain exists REF | delete REF | info REF [--json] | list [SERVICE] [--json]
keychain system list [--attr K=V]... [--match TEXT] [--json] | system get ID --reveal
keychain unlock [--create] | doctor [--json] | policy [REF [--op read|write]] | audit [-n N]
keychain install-skill | --version
common: --caller NAME, --store NAME, --no-prompt
```

Exit codes follow the agent-tools contract: 0 ok, 1 internal error, 2 usage, 4 not found,
5 no store reachable, 8 denied, 127 missing tool. keychain-cli adds 9: the store is locked.

The library API is `Keychain(caller).get/set/delete/exists/info/list/system_list`. `get`
returns a `Secret`, which prints as `Secret(***)` and refuses to be pickled. The value comes
out only through `.reveal()`.

## Security model

What keychain-cli protects against: secrets leaking into places they persist or get shared,
such as argv, shell history, logs, tracebacks, plaintext files, git, chat messages and agent
transcripts; and one utility reading another utility's secrets by mistake.

What it does not protect against: malicious code running as the same user. That code can talk
to the unlocked Secret Service, or run `security`, directly. The operating system's boundary
is the keyring lock (and, on macOS, item ACL dialogs). keychain-cli adds discipline on top of
that boundary; it is not a sandbox. Agent harness hooks are the place to block an agent from
going around it.

1. **Input.** A value enters only through stdin or a hidden `getpass` prompt. No option takes
   a value, and a test asserts this. On macOS the value travels to `security -i` over stdin,
   hex-encoded, never in argv.
2. **Output.** `get` refuses to print without `--reveal`. `exec` puts the value into the
   child's environment or stdin. By default it pipes the child's stdout and stderr through a
   streaming redactor, which replaces each injected value with `***` even when the value is
   split across two reads. It masks the raw value, the trimmed value, base64 at all three
   alignments (standard and URL-safe, as in HTTP Basic auth), the URL-quoted form, JSON and
   Python escapes, hex, and each line of a multi-line value. Values shorter than 4 bytes
   cannot be masked reliably, so `exec` refuses them. `--no-redact` (full TTY passthrough)
   counts as printing the value: inside an agent session it needs the reveal right (rule 4).
   A child writing directly to `/dev/tty` bypasses the pipes; agent harnesses do not give
   commands a TTY.
3. **Errors and logs.** Messages name refs, never values. Rejected arguments are not echoed,
   because a value pasted in the wrong place must not be printed a second time. An unexpected
   exception prints only its type (`KEYCHAIN_DEBUG=1` re-raises it). On macOS the
   `password:` line of `security -g` is removed from stderr before errors are classified.
   Core dumps are disabled (`RLIMIT_CORE=0`), and on Linux the process is marked
   non-dumpable.
4. **Callers and policy.** The caller comes from `--caller`, then `KEYCHAIN_CALLER`, then the
   default: `agent` inside an agent harness, otherwise `user`.
   - `user` may do everything.
   - Any other caller owns `<caller>/*`. Everything else needs a read or write glob in
     `~/.config/keychain-cli/policy.toml` under `[callers.<name>]`.
   - System items are never owned. A grant reaches them only through patterns that start
     with `system:`; `*` does not match them.
   - Every ref of a command is authorized before the first one touches the store, so a
     denied call never fetches, unlocks or prompts.
   - Inside an agent session, printing (`get --reveal`, `system get --reveal`,
     `exec --no-redact`) needs `reveal = true` in the caller's policy entry. It is never
     allowed for `agent` or `user`. Owning a namespace is not enough, because any process
     can claim a utility's name with `--caller`. Only the human edits the policy file.
     Redacted `exec` needs only read access.
   - `exec` removes `KEYCHAIN_CALLER` from the child's environment, so a child does not
     inherit its parent's identity.
   - Lookups re-check `service`/`account` exactly. A store that matches loosely (for
     example case-insensitively) cannot let `TG-CLI/x` act on `tg-cli/x`.
5. **Agent detection.** An agent session is recognised by the environment markers its harness
   exports: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `OMPCODE`, any `CODEX_*`, `OPENCODE`,
   `GEMINI_CLI`, `CURSOR_AGENT`, `PI_CODING_AGENT`. `KEYCHAIN_AGENT=1` forces agent mode;
   nothing switches a detected harness back to human mode. An agent session cannot claim
   the `user` caller.
6. **Audit.** Every get, set, delete, info, list, system access and exec is appended to
   `~/.local/state/keychain-cli/audit.jsonl` (directory 0700, file 0600). This includes
   refusals and a `get` without `--reveal`. Each line records the time, operation, ref,
   caller, agent flag, outcome, pid, parent pid and parent process name. Values are never
   recorded.
7. **Listing.** `list` shows only refs, labels and notes. `system list` shows only an
   allowlist of metadata attributes (url, server, username, schema, …), and only lets you
   filter on those attributes. Some apps keep secrets in attributes (for example
   passwords-app stores TOTP seeds in `otpauth`), so every other attribute is hidden. URL
   attributes lose their userinfo, query and fragment.
8. **Transport (Linux).** The Secret Service session uses the `plain` algorithm. It is safe
   for three reasons, all of which are checked:
   - the bus socket's peer runs as our uid (`SO_PEERCRED`), so a squatted abstract or stale
     bus address is refused;
   - the owner of `org.freedesktop.secrets` runs as our uid (`GetConnectionUnixUser`);
   - prompt signals are accepted only from that owner.
   That uid can already read every unlocked secret, so DH session encryption would not narrow
   who can read a value. It would also need AES, which the stdlib does not have.
9. **Memory.** Python cannot wipe immutable strings. A value lives in process memory for the
   duration of one command.
10. **Launcher.** `bin/keychain` runs `python3 -I`: PYTHONPATH, `PYTHON*` variables and user
    site-packages are ignored, so a project's `getpass.py` cannot load into this process. On
    macOS the backend runs `/usr/bin/security` by absolute path, never through a PATH
    lookup.

Environment variables read: `KEYCHAIN_CALLER`, `KEYCHAIN_STORE`, `KEYCHAIN_NO_PROMPT`,
`KEYCHAIN_AGENT`, `KEYCHAIN_DEBUG`, `XDG_CONFIG_HOME` (policy), `XDG_STATE_HOME` (audit),
`DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` (Linux bus), and the agent markers above.
A harness hook that wants to pin an agent's configuration strips these.

## Locked stores and headless sessions

- On a desktop, the login keyring is unlocked at login (pam_gnome_keyring on Linux,
  loginwindow on macOS).
- A GUI unlock prompt is used only when a display is present and `--no-prompt` is not set.
  Otherwise a locked store fails immediately with exit 9. SSH, cron and systemd jobs never
  hang on a dialog nobody can see.
- `keychain unlock` (Linux, gnome-keyring) reads the keyring password on the TTY and passes it
  to gnome-keyring's master-password D-Bus interface. This works over `ssh -t`.
  `keychain unlock --create` creates the default "Login" collection on a server that has
  none. On macOS, `keychain unlock` runs `security unlock-keychain`, which prompts on the TTY.
- Without `DBUS_SESSION_BUS_ADDRESS` (cron, plain systemd units), the client falls back to
  `$XDG_RUNTIME_DIR/bus`, then to `/run/user/<uid>/bus`.
- To keep the user bus and the unlocked keyring alive between logins, run
  `loginctl enable-linger $USER`. Ubuntu ships `gnome-keyring-daemon.socket` as a user unit,
  which starts the daemon on first use.
- `keychain doctor` prints the exact steps for the current machine.

## System passwords: what is reachable

| Source | Linux | macOS |
| --- | --- | --- |
| Apple Passwords / iCloud Keychain | yes, via passwords-app, which syncs them into the "iCloud Passwords" Secret Service collection (schema `io.github.alex_mextner.Passwords`) | no: `security` cannot reach the data-protection (iCloud) keychain |
| Safari / legacy internet passwords | — | `inet` items in the login keychain; `system get` shows the macOS "allow" dialog (it cannot appear over SSH) |
| Chrome / Chromium saved passwords | no: the passwords live in Chrome's own encrypted database, and the Secret Service holds only the database key (`chrome_libsecret_os_crypt_password_v2`). keychain-cli does not decrypt browser databases | same: "Chrome Safe Storage" is a key, not the passwords |
| Firefox | no (its own NSS store) | no |
| Wi-Fi | NetworkManager keeps system connections root-only; secrets saved per user show up as system items | `genp` "AirPort network password" items; reading one shows the dialog |
| GNOME Online Accounts, Remote Desktop, portals | listed as system items; reading one needs a policy grant | — |

## Not in scope

Windows. Encrypted file fallback stores. Decrypting browser password databases. Syncing
between machines (passwords-app covers Apple to Linux).
