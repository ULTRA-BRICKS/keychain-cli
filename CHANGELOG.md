# Changelog

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
