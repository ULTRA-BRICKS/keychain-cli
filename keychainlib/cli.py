"""`keychain` command line: a thin argparse layer over `keychainlib.api.Keychain`.

Secret values enter only through stdin or a hidden TTY prompt and leave only through
`get --reveal` (stdout) or `exec` (a child's env/stdin). No code path here formats a value
into a message.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from collections.abc import Callable

from . import __version__, approval
from .api import Keychain
from .audit import Audit
from .backends import SAFE_SYSTEM_ATTRIBUTES
from .errors import EXIT_CODES, EXIT_INTERNAL, EXIT_OK, KeychainError, UsageError
from .origins import normalize_origin
from .policy import READ, WRITE, Policy, policy_path
from .refs import SystemRef, parse_item_ref, parse_ref, valid_service

MAX_SECRET = 64 * 1024

EPILOG = (
    "exit codes:\n"
    + "\n".join(f"  {code:<4}{text}" for code, text in EXIT_CODES.items())
    + """

refs: SERVICE/ACCOUNT for keychain-cli items (e.g. tg-cli/bot-token), system:ID for
items other apps stored (ids from `keychain system list`).
values are read from stdin or a hidden prompt, never from arguments."""
)


def _common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("common options")
    g.add_argument(
        "--caller",
        help="the utility asking (default: $KEYCHAIN_CALLER, else "
        "`user`, or `agent` inside an agent harness)",
    )
    g.add_argument(
        "--store",
        default=os.environ.get("KEYCHAIN_STORE"),
        help="Linux: Secret Service collection label/id; macOS: keychain file "
        "(default: the login/default store)",
    )
    g.add_argument(
        "--no-prompt",
        action="store_true",
        default=os.environ.get("KEYCHAIN_NO_PROMPT") == "1",
        help="never show a GUI unlock prompt; fail with exit 9 instead",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keychain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Secrets for rig utilities from the OS keychain (macOS Keychain, Linux Secret Service).",
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"keychain {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(
            name,
            help=help_text,
            description=help_text,
            epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        _common(p)
        return p

    p = add("set", "store a secret; the value comes from stdin or a hidden prompt")
    p.add_argument("ref")
    p.add_argument("--label", help="human-readable label (one line)")
    p.add_argument("--note", help="free-text note (one line, not secret)")
    p.add_argument(
        "--raw", action="store_true", help="keep stdin byte-exact (default strips one trailing newline)"
    )
    p.add_argument(
        "--origin",
        help="the website this credential belongs to (https://site.tld); `fill` types it "
        "only there. An empty string removes it",
    )

    p = add("get", "print a secret to stdout (needs --reveal); prefer `exec`")
    p.add_argument("ref")
    p.add_argument("--reveal", action="store_true", help="yes, print the value to stdout")

    p = add("exec", "run a command with secrets injected into its env/stdin")
    p.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=REF",
        help="set env var NAME to the secret REF (repeatable)",
    )
    p.add_argument("--stdin", metavar="REF", help="write the secret REF to the command's stdin")
    p.add_argument(
        "--no-redact",
        action="store_true",
        help="do not mask injected values in the command's output (TTY passthrough)",
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command [args...]")

    def browser_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("ref")
        p.add_argument(
            "--cdp",
            required=True,
            metavar="URL",
            help="DevTools endpoint on loopback: http://127.0.0.1:PORT or ws://127.0.0.1:PORT/devtools/browser/…",
        )
        where = p.add_mutually_exclusive_group(required=True)
        where.add_argument("--selector", metavar="CSS", help="the field (document.querySelector syntax)")
        where.add_argument("--focused", action="store_true", help="the field that has keyboard focus")
        p.add_argument("--target", metavar="ID", help="the tab's CDP target id (default: the only match)")
        p.add_argument("--origin", help="also require the field's page to have exactly this origin")

    p = add("fill", "type a credential into a browser field over CDP (the value is never printed)")
    browser_args(p)
    p.add_argument("--field", choices=["password", "username"], default="password")

    p = add("capture", "store a browser field's value over CDP, bound to the page's origin")
    browser_args(p)
    p.add_argument("--label", help="human-readable label (one line)")

    p = add("exists", "exit 0 if the secret exists, 4 if not")
    p.add_argument("ref")

    p = add("delete", "delete a secret")
    p.add_argument("ref")

    p = add("info", "show a secret's metadata (never the value)")
    p.add_argument("ref")
    p.add_argument("--json", action="store_true")

    p = add("list", "list keychain-cli secrets (metadata only)")
    p.add_argument("service", nargs="?")
    p.add_argument("--json", action="store_true")

    # no _common at this level: argparse would let the nested parser's defaults overwrite it
    p = sub.add_parser("system", help="items other apps stored (website, Wi-Fi, app passwords)")
    ssub = p.add_subparsers(dest="system_command", metavar="<list|get>", required=True)
    sl = ssub.add_parser("list", help="list system items (safe attributes only)")
    _common(sl)
    sl.add_argument(
        "--attr",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="exact attribute match (repeatable), e.g. --attr server=github.com",
    )
    sl.add_argument("--match", help="case-insensitive substring of the label or attributes")
    sl.add_argument("--json", action="store_true")
    sg = ssub.add_parser("get", help="print a system item's value (needs --reveal)")
    _common(sg)
    sg.add_argument("id")
    sg.add_argument("--reveal", action="store_true")

    p = add("unlock", "unlock the keyring (asks for its password on the TTY)")
    p.add_argument(
        "--create",
        action="store_true",
        help="Linux: create a default keyring if there is none (headless servers)",
    )

    p = add("doctor", "diagnose the secret store, session and policy")
    p.add_argument("--json", action="store_true")

    p = add("policy", "show the access policy, or check one access")
    p.add_argument("check", nargs="?", metavar="REF", help="a ref to check for the caller")
    p.add_argument("--op", choices=[READ, WRITE], default=READ)

    p = add("audit", "show the access journal (no values are ever recorded)")
    p.add_argument("-n", type=int, default=20, help="last N entries (default 20)")
    p.add_argument("--json", action="store_true")

    add("install-skill", "register the keychain agent skill with agent harnesses")
    return parser


# ── commands ─────────────────────────────────────────────────────────────────


def _read_value(ref: str, raw: bool) -> bytes:
    if sys.stdin.isatty():
        first = getpass.getpass(f"Secret for {ref}: ")
        if getpass.getpass("Repeat: ") != first:
            raise UsageError("the two entries do not match")
        return first.encode("utf-8")
    data = sys.stdin.buffer.read(MAX_SECRET + 1)
    if len(data) > MAX_SECRET:
        raise UsageError(f"secret larger than {MAX_SECRET} bytes")
    if not raw:
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
    return data


def _check_reveal(kc: Keychain, ref, flag: bool) -> None:
    if not flag:
        kc.audit.record("reveal", str(ref), kc.caller, "NoRevealFlag", agent=kc.agent, backend="")
        raise UsageError(
            "refusing to print a secret without --reveal",
            fix=f"inject it instead: keychain exec --env NAME={ref} -- command; "
            "or add --reveal when stdout goes where it should",
        )
    kc.authorize("reveal", [ref], READ, reveal=True)


def _write_value(value: bytes) -> None:
    out = sys.stdout.buffer
    out.write(value)
    if sys.stdout.isatty():
        out.write(b"\n")
    out.flush()


def _ts(value: int | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value)) if value else "-"


def cmd_set(kc: Keychain, a: argparse.Namespace) -> int:
    ref = parse_item_ref(a.ref)
    origin = normalize_origin(a.origin) if a.origin else a.origin  # reject before the prompt
    kc.authorize("set", [ref], WRITE)  # refuse before asking for the value
    kc.set(ref, _read_value(str(ref), a.raw), label=a.label, note=a.note, origin=origin)
    print(f"stored {ref}", file=sys.stderr)
    return EXIT_OK


def cmd_fill(kc: Keychain, a: argparse.Namespace) -> int:
    selector = None if a.focused else a.selector
    result = kc.fill(a.ref, a.cdp, selector, field=a.field, origin=a.origin, target=a.target)
    print(json.dumps(result, ensure_ascii=False))
    return EXIT_OK


def cmd_capture(kc: Keychain, a: argparse.Namespace) -> int:
    selector = None if a.focused else a.selector
    result = kc.capture(a.ref, a.cdp, selector, label=a.label, origin=a.origin, target=a.target)
    print(json.dumps(result, ensure_ascii=False))
    return EXIT_OK


def cmd_get(kc: Keychain, a: argparse.Namespace) -> int:
    ref = parse_ref(a.ref)
    _check_reveal(kc, ref, a.reveal)
    _write_value(kc.get(ref, purpose="reveal").reveal_bytes())
    return EXIT_OK


def cmd_exec(kc: Keychain, a: argparse.Namespace) -> int:
    from . import execution

    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        raise UsageError("no command given", fix="keychain exec --env NAME=REF -- command args")
    if not a.env and not a.stdin:
        raise UsageError("nothing to inject", fix="add --env NAME=REF and/or --stdin REF")
    bindings = []
    for i, binding in enumerate(a.env, 1):
        name, sep, ref = binding.partition("=")
        if not sep or not execution.valid_env_name(name):
            # never echo the argument: a value pasted here by mistake must not be printed again
            raise UsageError(f"--env #{i} must be NAME=REF with NAME a valid variable name")
        bindings.append((name, parse_ref(ref)))
    stdin_ref = parse_ref(a.stdin) if a.stdin else None
    refs = [r for _, r in bindings] + ([stdin_ref] if stdin_ref else [])
    purpose = f"exec:{os.path.basename(cmd[0])}"
    # every ref is authorized before the first one touches (and maybe unlocks) the store; an
    # unredacted child can print the value, so --no-redact needs the right to reveal
    kc.authorize(purpose, refs, READ, reveal=a.no_redact)
    env_secrets = {name: kc.get(r, purpose=purpose) for name, r in bindings}
    stdin_secret = kc.get(stdin_ref, purpose=purpose) if stdin_ref else None
    return execution.run(cmd, env_secrets, stdin_secret, redact=not a.no_redact)


def cmd_exists(kc: Keychain, a: argparse.Namespace) -> int:
    return EXIT_OK if kc.exists(a.ref) else 4


def cmd_delete(kc: Keychain, a: argparse.Namespace) -> int:
    kc.delete(a.ref)
    print(f"deleted {a.ref}", file=sys.stderr)
    return EXIT_OK


def cmd_info(kc: Keychain, a: argparse.Namespace) -> int:
    info = kc.info(a.ref)
    if a.json:
        print(json.dumps(info.as_dict(), ensure_ascii=False))
    else:
        print(
            f"ref:      {info.ref}\nlabel:    {info.label}\nnote:     {info.note}\n"
            f"origin:   {info.origin or '-'}\n"
            f"created:  {_ts(info.created)}\nmodified: {_ts(info.modified)}"
        )
    return EXIT_OK


def cmd_list(kc: Keychain, a: argparse.Namespace) -> int:
    if a.service and not valid_service(a.service):
        raise UsageError(f"invalid service name {a.service!r}")
    items = kc.list(a.service)
    if a.json:
        print(json.dumps([i.as_dict() for i in items], ensure_ascii=False))
        return EXIT_OK
    if not items:
        print("no secrets" + (f" under {a.service}/" if a.service else ""), file=sys.stderr)
    for i in items:
        print(f"{i.ref}\t{i.label}\t{i.note}".rstrip("\t"))
    return EXIT_OK


def _kv(pairs: list[str]) -> dict[str, str]:
    out = {}
    for pair in pairs:
        k, sep, v = pair.partition("=")
        if not sep or not k:
            raise UsageError("--attr expects KEY=VALUE")
        if k not in SAFE_SYSTEM_ATTRIBUTES:
            raise UsageError(
                f"--attr can filter only on listed attributes, not {k!r}",
                why="matching on hidden attributes would reveal their values bit by bit",
            )
        out[k] = v
    return out


def cmd_system(kc: Keychain, a: argparse.Namespace) -> int:
    if a.system_command == "get":
        ref = SystemRef(a.id.removeprefix("system:"))
        parse_ref(str(ref))  # validate the id charset
        _check_reveal(kc, ref, a.reveal)
        _write_value(kc.get(ref, purpose="reveal").reveal_bytes())
        return EXIT_OK
    items = kc.system_list(_kv(a.attr))
    if a.match:
        needle = a.match.lower()
        items = [
            i
            for i in items
            if needle in i.label.lower() or any(needle in v.lower() for v in i.attributes.values())
        ]
    if a.json:
        print(json.dumps([i.as_dict() for i in items], ensure_ascii=False))
        return EXIT_OK
    for i in items:
        shown = " ".join(f"{k}={v}" for k, v in i.attributes.items() if k != "xdg:schema")
        lock = " [locked]" if i.locked else ""
        print(f"system:{i.id}\t{i.label}{lock}\t{i.kind}\t{shown}".rstrip())
    return EXIT_OK


def cmd_unlock(kc: Keychain, a: argparse.Namespace) -> int:
    print(kc.backend.unlock(create=a.create), file=sys.stderr)
    return EXIT_OK


def cmd_doctor(kc: Keychain, a: argparse.Namespace) -> int:
    from .doctor import diagnose, render

    report = diagnose(kc)
    print(json.dumps(report, ensure_ascii=False, indent=1) if a.json else render(report))
    return EXIT_OK if report.get("ok") else 5


def cmd_policy(kc: Keychain, a: argparse.Namespace) -> int:
    if a.check:
        ref = parse_ref(a.check)
        allowed = kc.policy.allows(kc.caller, a.op, ref)
        reveal = kc.may_reveal()
        print(
            f"caller={kc.caller} {a.op} {ref}: {'allowed' if allowed else 'denied'}; "
            f"print in this session: {'yes' if allowed and reveal else 'no'}"
        )
        return EXIT_OK if allowed else 8
    print(f"policy file: {policy_path()} ({'present' if policy_path().exists() else 'absent'})")
    print(f"caller: {kc.caller}  agent session: {'yes' if kc.agent else 'no'}")
    print(
        "rules: `user` (human, no agent harness) may do everything; every other caller "
        "owns SERVICE/* where SERVICE is its name; other refs need [callers.<name>] "
        "read/write globs."
    )
    command, source = approval.resolve_command(kc.policy.approval_cmd, agent=kc.agent)
    print(
        f"fill approval: `{' '.join(command)}` (from {source}), "
        f"{kc.policy.approval_timeout}s; asked for every caller but `user` unless approve = false"
    )
    for name, grant in sorted(kc.policy.callers.items()):
        print(
            f"  [{name}] read={list(grant.read)} write={list(grant.write)} "
            f"reveal={grant.reveal} fill={list(grant.fill)} approve={grant.approve}"
        )
    return EXIT_OK


def cmd_audit(kc: Keychain, a: argparse.Namespace) -> int:
    entries = kc.audit.tail(max(a.n, 1))
    if a.json:
        print(json.dumps(entries, ensure_ascii=False))
        return EXIT_OK
    for e in entries:
        print(
            f"{e.get('ts')} {e.get('caller')}{' (agent)' if e.get('agent') else ''} "
            f"{e.get('op')} {e.get('ref')} -> {e.get('outcome')} "
            f"[parent {e.get('parent') or '?'}]"
        )
    return EXIT_OK


def cmd_install_skill(_kc: Keychain | None, _a: argparse.Namespace) -> int:
    from .install import install_skill

    return install_skill()


COMMANDS: dict[str, Callable[[Keychain, argparse.Namespace], int]] = {
    "set": cmd_set,
    "get": cmd_get,
    "exec": cmd_exec,
    "exists": cmd_exists,
    "fill": cmd_fill,
    "capture": cmd_capture,
    "delete": cmd_delete,
    "info": cmd_info,
    "list": cmd_list,
    "system": cmd_system,
    "unlock": cmd_unlock,
    "doctor": cmd_doctor,
    "policy": cmd_policy,
    "audit": cmd_audit,
}


def _no_core_dumps() -> None:
    """A crash must not write fetched values or typed passwords into a core file; on Linux
    also mark the process non-dumpable, which hides /proc/<pid>/mem and environ from ptrace."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
        except (OSError, AttributeError):
            pass


def main(
    argv: list[str] | None = None, keychain_factory: Callable[[argparse.Namespace], Keychain] | None = None
) -> int:
    parser = build_parser()
    _no_core_dumps()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_OK
    try:
        if args.command == "install-skill":
            return cmd_install_skill(None, args)
        if keychain_factory is not None:
            kc = keychain_factory(args)
        else:
            kc = Keychain(
                args.caller,
                store=args.store,
                interactive=not args.no_prompt,
                policy=Policy.load(),
                audit=Audit(),
            )
        return COMMANDS[args.command](kc, args)
    except KeychainError as exc:
        print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:
        print(f"keychain: internal error ({type(exc).__name__})", file=sys.stderr)
        if os.environ.get("KEYCHAIN_DEBUG") == "1":
            raise
        return EXIT_INTERNAL
