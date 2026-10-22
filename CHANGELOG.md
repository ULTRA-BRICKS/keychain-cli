# Changelog

## 0.2.0 — 2026-10-22

- Human approval before every `fill` by a caller other than `user`: keychain runs a
  replaceable command (policy `approval_cmd`, else `KEYCHAIN_APPROVAL_CMD` outside agent
  sessions, else `tg-ctl ask`) with the prompt as its argument and
  `KEYCHAIN_APPROVAL_TIMEOUT` in its environment, and fills only on exit 0 (otherwise exit 8;
  missing command 127). It runs after the page and credential check out and before the value is
  read. `approval_timeout` and `[callers.X] approve = false` (the human exempts a caller) are
  new policy keys; the journal records `approval`. Nothing in keychain is tied to Telegram.
- Hardening from the reviews, all in `fill`/`capture`: a selector that matches twice in one
  frame is ambiguous (exit 2) instead of silently taking the first; the field and the stored
  item are re-checked after the approval wait, and the write itself refuses, inside the browser,
  a field that became disabled, read-only or unmasked; a credential replaced (value and site)
  during the fill is not typed; `capture` keeps an existing binding to the page's site instead
  of narrowing it to a subdomain, and refuses values over 64 KiB; a borrowed `Cdp` connection
  keeps the sessions its owner opened; a browser that died mid-call is exit 5, never exit 0; the
  approver does not inherit `KEYCHAIN_CALLER`. A stored value with a line break is refused (an `<input>` would drop it; this needs the value, so it happens after the approval); `tg-ctl ask` as the approver gets `--timeout` from `approval_timeout`.
- `keychain fill REF --cdp URL (--selector CSS | --focused)` writes a credential into a
  Chromium field over the DevTools protocol, inside the keychain process: the value never
  reaches argv, stdout, logs, the journal or an agent's context. It sets the value on the
  checked element itself (not keystrokes, which follow focus) and fires `input`/`change`. It
  fills only a visible, masked `type=password` field (or a username/email field with
  `--field username`) on an https page whose every frame is on the credential's host (or a
  subdomain the grant names), refuses an invalid or unverifiable TLS certificate and a frame
  chain it cannot resolve, and clears the field if a script unmasks it. Loopback CDP endpoints
  only, owned by our uid on Linux. See SPEC "Browser".
- `keychain capture REF --cdp URL --selector CSS` stores a field's value bound to the page's
  origin. `keychain set --origin URL` binds a credential to a website; `info` shows it.
- Policy: `[callers.X] fill = ["https://site.tld", …]`. Fill needs it for every caller but
  `user` (who gets only the credential's exact host), plus the read right on the ref: whoever
  drives the browser can read a filled field back, so filling is reading. Printing stays
  refused in agent sessions. Grants are normalized (case, trailing slash, default port,
  punycode for internationalized hosts, IPv6 brackets); a grant that is not an origin, or a
  host whose punycode would be ambiguous (`faß.de`), is a policy error.
- A `system:` credential is bound to the first of its URL attributes that parses (KeePassXC's
  `URL` included), or to a macOS internet password's protocol, server and port. Its collection
  is unlocked first, so a locked keyring is exit 9, not "not bound to a website".
- Python: `Keychain(caller).fill(ref, cdp, selector, field=…)` takes a DevTools URL or a CDP
  session object with `send(method, params)` and `on(event, handler)` (Playwright's sync
  `new_cdp_session`; without `on` the TLS state is unknown and the fill is refused);
  `Keychain.capture(...)`; `Keychain.set(..., origin=…)`. On a connection the caller keeps,
  the tab sessions a fill opened are detached afterwards and our event handlers go inert.
- Linux: writers of one ref now take a per-ref `flock` in `$XDG_RUNTIME_DIR/keychain-cli`, so
  parallel `set`/`delete` on one machine are serialized. 0.1.1 tolerated the race but could
  leave two items (seen once in a live check); duplicates from writers the lock cannot see
  are still folded into the oldest item.
- `system list` and `system get` tolerate an item another app deletes meanwhile (no more
  exit 1); a malformed `DBUS_SESSION_BUS_ADDRESS` is exit 5, not 1; `install-skill` no
  longer overwrites another skill named `keychain` or crashes on a file in its way (exit 2).
- Tests: an integration suite (`KEYCHAIN_INTEGRATION=1`, `tests/integration/`) runs the real
  binary on a throwaway gnome-keyring collection with real consumers (curl via `exec`, a second
  Python utility, an agent session, a headless locked store unlocked over a pseudo-terminal,
  parallel writers) and `fill`/`capture` in headless Chromium on a local self-signed https
  login page, including origin spoofing, a cross-origin iframe, a non-password field and a
  missing grant. CI runs it in a new `integration` job under `dbus-run-session`. Unit tests
  cover the `set` convergence logic without a bus. Ruff now enforces the 110-column limit.

## 0.1.1 — 2026-10-17

- Linux: concurrent `keychain set` of the same ref no longer fails with an internal error
  (found by the live E2E run: 4 of 10 parallel writers exited 1). Writers now converge on
  the oldest item, tolerate items deleted under them, and retry; `delete` tolerates a
  concurrent delete. A live test runs ten parallel writers.

## 0.1.0 — 2026-10-17

First release.

- `keychain set/get/exec/exists/delete/info/list` over the Linux Secret Service (a stdlib
  D-Bus client) and the macOS Keychain (`security`, values passed hex-encoded over stdin).
- `keychain exec` injects secrets into a child process's environment or stdin, and by
  default masks them in the child's output.
- `keychain system list/get` for passwords other apps stored. Only safe metadata attributes
  are listed.
- Callers and policy: each utility owns `<name>/*`; other access is granted in
  `~/.config/keychain-cli/policy.toml`; an agent session cannot print values.
- A value-free audit journal; `keychain doctor`; `keychain unlock [--create]` for headless
  Linux; `keychain install-skill`.
