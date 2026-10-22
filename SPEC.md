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
  and optional `note` and `origin`. It lives in the default collection, or in `--store` (a
  collection label or id).
- macOS: the item is a generic password with service `service`, account `account` and kind
  (`-D`) `keychain-cli`. The label and the note map to the keychain's label and comment; the
  origin to the generic attribute (`-G`, `gena`).
- `origin` (`https://host[:port]`) binds a credential to a website for `keychain fill`.
- A system item is anything another app stored: website passwords (synced by passwords-app,
  stored by browsers), Wi-Fi passwords, app tokens. It is addressed as `system:<id>`, using
  the id that `keychain system list` prints. On Linux the id is `<collection>/<item>`, for
  example `login/12`. On macOS it is `inet:<server>/<account>` or `genp:<service>/<account>`,
  percent-encoded.

## Commands

```
keychain set REF [--label L] [--note N] [--origin URL] [--raw]   value from stdin or a TTY prompt
keychain get REF --reveal                         value to stdout (no newline unless a TTY)
keychain exec [--env NAME=REF]... [--stdin REF] [--no-redact] -- CMD...
keychain exists REF | delete REF | info REF [--json] | list [SERVICE] [--json]
keychain fill REF --cdp URL (--selector CSS | --focused) [--field password|username]
              [--origin URL] [--target TAB]       type it into a browser field (see Browser)
keychain capture REF --cdp URL (--selector CSS | --focused) [--label L] [--origin URL] [--target TAB]
keychain system list [--attr K=V]... [--match TEXT] [--json] | system get ID --reveal
keychain unlock [--create] | doctor [--json] | policy [REF [--op read|write]] | audit [-n N]
keychain install-skill | --version
common: --caller NAME, --store NAME, --no-prompt
```

Exit codes follow the agent-tools contract: 0 ok, 1 internal error, 2 usage, 4 not found,
5 no store reachable, 8 denied, 127 missing tool. keychain-cli adds 9: the store is locked.

The library API is `Keychain(caller).get/set/delete/exists/info/list/system_list/fill/capture`.
`get` returns a `Secret`, which prints as `Secret(***)` and refuses to be pickled. The value
comes out only through `.reveal()`.

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
   - `fill` needs a `fill` grant naming the page's origin for every caller but `user`
     (Browser section). It does not need `reveal`: the value goes into the page.
   - Every `fill` by a caller other than `user` is confirmed by a human first, through the
     replaceable approval command (Browser section, "Approval").
   - `exec` removes `KEYCHAIN_CALLER` from the child's environment, so a child does not
     inherit its parent's identity.
   - Lookups re-check `service`/`account` exactly. A store that matches loosely (for
     example case-insensitively) cannot let `TG-CLI/x` act on `tg-cli/x`.
5. **Agent detection.** An agent session is recognised by the environment markers its harness
   exports: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `OMPCODE`, any `CODEX_*`, `OPENCODE`,
   `GEMINI_CLI`, `CURSOR_AGENT`, `PI_CODING_AGENT`. `KEYCHAIN_AGENT=1` forces agent mode;
   nothing switches a detected harness back to human mode. An agent session cannot claim
   the `user` caller.
6. **Audit.** Every get, set, delete, info, list, system access, exec, fill and capture (with
   the page's origin and the selector) is appended to
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
`DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` (Linux bus, write locks), `KEYCHAIN_FILL_TEST`
(loopback test pages for `fill`, see Browser), `KEYCHAIN_APPROVAL_CMD` (the approval command,
outside agent sessions only), and the agent markers above. A harness hook that
wants to pin an agent's configuration strips these.

## Concurrent writers

The Secret Service has no compare-and-set: two processes that search for a ref, find nothing
and create it leave two items. Writers of one ref therefore take an exclusive `flock` on
`$XDG_RUNTIME_DIR/keychain-cli/<sha256(collection, service, account)>.lock` (falling back to
`/run/user/<uid>`, then a private directory in the temp dir; the directory must be 0700 and
ours). `set` and `delete` hold it around search-and-write, so every keychain-cli writer on the
machine is serialized. Writers the lock cannot see (another app, another machine syncing the
same collection) are still folded: after a create, every writer keeps the oldest item and
deletes the rest. macOS `add-generic-password -U` is a single keychain call.

## Browser

`keychain fill` types a credential into a field of a Chromium-family browser over the Chrome
DevTools Protocol (CDP); `keychain capture` stores a field's value. Both run in the keychain
process with a stdlib CDP client (WebSocket over a socket), so the value travels store → the
checked element's `value` (`Runtime.callFunctionOn` on that element, then `input`/`change`
events; not `Input.insertText`, which goes to whatever has focus when it arrives) or field →
store, and never through argv, stdout, logs, the audit journal or an agent's context. stdout
carries only `{"filled":true,"selector":…,"origin":…}` or
`{"captured":true,"ref":…,"origin":…}`.

- **Endpoint.** `--cdp` is `http://127.0.0.1:PORT` (resolved through `/json/version`) or the
  browser's `ws://127.0.0.1:PORT/devtools/browser/…` URL. Only loopback hosts are accepted; on
  Linux the process listening on that TCP connection must run as our uid (from
  `/proc/net/tcp`), so another user cannot pose as a browser and receive values. macOS has no
  such check.
- **Which field.** `--selector` is looked up in every frame of every tab (cross-site iframes
  through auto-attached child sessions), `--focused` follows `document.activeElement` into
  frames. Exactly one match is required, counting several matches inside one frame too (exit 2
  otherwise, also for an empty field to capture);
  `--target` picks a tab (it needs a DevTools URL: a session object is one tab). Lookups run
  in an isolated world, so page scripts cannot redefine `querySelector` or the element's
  properties for us; frame URLs come from the browser's frame tree, not `document.URL`.
- **Origin binding (phishing).** The credential's origin is its `origin` attribute, or for a
  `system:` item the first of `url`, `URL` (KeePassXC), `origin_url`, `signon_realm`, `uri`
  that parses, or a macOS internet password's protocol, server and port; a credential without
  one is refused. Hosts are compared in punycode, as the browser reports them; an
  internationalized name whose punycode Python and the browser would spell differently
  (`ß`, `ς`, joiners, compatibility characters) is refused rather than guessed. The field's
  frame and every frame above it up to the top must be https, with the credential's scheme and
  port, on the credential's host or a subdomain of it. There is no
  Public Suffix List (none in the stdlib, and a vendored one goes stale); instead a subdomain is
  reachable only when the `fill` grant names it. `--origin` additionally requires an exact
  origin; it cannot widen anything. The tab's TLS state (`Security.visibleSecurityStateChanged`)
  must not report a certificate error, which catches browsers started with
  `--ignore-certificate-errors` or a clicked-through interstitial.
- **Policy.** `[callers.X] fill = ["https://site.tld", "https://*.site.tld"]` lists origins
  (globs) caller X may fill into; every frame origin above must match. Grants are read in that
  form (lowercase, punycode, no trailing slash or default port); one that is not
  `scheme://host[:port]` makes the policy file invalid. Owning a namespace does
  not grant fill. The caller also needs the read right on the ref (own namespace or a `read`
  grant; `system:` patterns for system items): the agent that drives the browser can read a
  filled field back over CDP, so fill is no stronger a boundary than read. What fill adds is
  the site binding and keeping the value out of the transcript by default. `user` (a human
  outside an agent session) needs no grant but gets only the credential's exact host. The
  policy and the frames are checked before the store is touched; the frames are checked again
  right before writing. The store is unlocked (or exit 9) before the credential's origin is
  looked up, so a locked store never looks like a missing credential.
- **Approval (a replaceable human channel).** keychain does not know how to reach a person:
  it runs a command. The default is tg-cli's blocking question, `tg-ctl ask`; any component
  that can ask a human and report the answer by exit status can replace it, so nothing in
  keychain is tied to Telegram. Every fill by a caller other than `user` is confirmed this
  way, after the page and the credential have been checked against each other (nobody is asked
  about a fill that would be refused anyway) and before the value is fetched from the store.
  The page is checked again after the answer, which may take minutes.
  - *Which command*, first match wins: `approval_cmd` in the policy file (a string split like
    a shell line, without a shell, or a list of strings); `KEYCHAIN_APPROVAL_CMD` in the
    environment, ignored inside agent sessions because an agent that could set it would approve
    itself; `tg-ctl ask`. `approval_timeout` (seconds, 1–900, default 300) bounds the wait. A
    future resolver (rig providers) supplies the command in the first two places.
  - *Contract.* argv is the command plus one argument, the prompt: one sentence naming the
    caller, the ref, the origin and the field kind, never a value (the selector is left out,
    since the agent chooses it). The environment gets `KEYCHAIN_APPROVAL_TIMEOUT` (seconds), and
    `KEYCHAIN_APPROVAL_CALLER`, `KEYCHAIN_APPROVAL_REF`, `KEYCHAIN_APPROVAL_ORIGIN` for
    channels that want data instead of a sentence. stdin is empty, stdout and stderr are
    discarded. Exit status 0 is approval; anything else, including a timeout (the command is
    killed after the timeout plus 15 s) or a crash, is a refusal: exit 8 `did not approve`.
    A missing or non-executable command is exit 127. The default command additionally gets
    `--timeout SEC`, which is how `tg-ctl ask` takes its limit.
  - *Exemption.* `[callers.X] approve = false` skips the question for that caller. Only the
    human edits the policy file; `user` is a human at a terminal and is never asked.
  - *Audit.* The `fill` entry carries `approval`: `approved`, `asked via <source>` (refused or
    failed) or `not required`.
  - *Trust.* The approver is found through the same `PATH` the caller has, and a process with
    our uid can replace it: approval protects against an agent acting on its own (a
    prompt-injected one included) and against mistakes, not against hostile code running as the
    user, which this tool never claimed to stop (see the first paragraph). The approver gets
    our environment minus `KEYCHAIN_CALLER`.
- **Field.** Password: `<input type=password>`, enabled, writable, not `visibility:hidden`,
  with a layout box, and accepting focus. Username (`--field username`): `type=text|email`
  with `autocomplete` containing `username` or `email` (or `type=email`). The old content is
  selected and replaced. Afterwards the field must still be `type=password` (a script that
  flips it to `text` would expose the value on screenshots) and hold exactly as many characters
  as were typed; otherwise it is cleared and the command fails. The value is never read back.
  The checks run again after the approval wait, and the write itself refuses (inside the
  browser, in the same call) a field that became disabled, read-only or no longer a masked
  password. If the stored item was replaced meanwhile (value and site change together), the fill
  is refused rather than typing the new value under the old origin's checks. The login name is
  its own ref: a ref holds one value, and `--field username` only changes what the field must be.
- **Capture.** Needs the write right on REF. The field (`<input>` or `<textarea>`) must be on
  an https page and hold at most 64 KiB; the stored item is bound to the field's frame origin,
  or keeps its existing binding when that site (or a parent of the page's host) already owns
  it, so capturing on a subdomain does not narrow it. An existing item bound to another site is
  not overwritten; the binding is read again right before the write, which narrows (a lock
  across the browser round trip would not be sound) but does not close a concurrent writer's window.
- **Test pages.** With `KEYCHAIN_FILL_TEST=1`, loopback pages (`localhost`, `*.localhost`,
  `127.0.0.0/8`, `::1`) may be plain http or carry a self-signed certificate. Nothing else is
  relaxed, so the variable cannot open a real site to an insecure page.
- **Out of scope.** The page's own scripts can read a field they own; the site is the user's
  trusted site. TLS state is read once per fill (fail closed when the browser does not report
  it; a Playwright session needs `on(event, handler)` for that). Playwright's CDP
  session (`page.context.new_cdp_session(page)`) reaches only frames in the page's own process,
  so cross-site iframes are not found through it. Exit codes: 2 no or several fields, 4 no
  credential, 5 no browser, 8 refused (policy, origin, field, TLS), 9 locked store.

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
