"""A stand-in for macOS /usr/bin/security, faithful to the output formats keychain-cli parses.

Formats follow Apple's SecurityTool sources (keychain_utilities.c print_buffer,
keychain_find.c do_password_item_printing, security.c split_line for `-i`). State lives in a
JSON file (FAKE_SECURITY_STATE); every argv is appended to FAKE_SECURITY_ARGV_LOG so tests can
prove a secret never appears on a command line.
"""

from __future__ import annotations

import getopt
import json
import os
import shlex
import sys

STATE = os.environ["FAKE_SECURITY_STATE"]
ARGV_LOG = os.environ.get("FAKE_SECURITY_ARGV_LOG")


def print_buffer(data: bytes) -> str:
    hexed = any(not (32 <= c <= 126) or c == 92 for c in data)
    ascii_ = any(32 <= c <= 126 and c != 92 for c in data)
    out = ""
    if hexed:
        out += "0x" + data.hex().upper() + (" " if ascii_ else "") + " "
    if ascii_:
        body = "".join(chr(c) if 32 <= c <= 126 and c != 92 else f"\\{c:03o}" for c in data)
        out += '"' + body + '"'
    return out


def load() -> list[dict]:
    try:
        with open(STATE) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []


def save(items: list[dict]) -> None:
    with open(STATE, "w") as fh:
        json.dump(items, fh)


def fail(msg: str, rc: int) -> int:
    print(f"security: {msg}", file=sys.stderr)
    return rc


NOT_FOUND = "SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
ATTRS = {"genp": ["acct", "desc", "icmt", "labl", "svce"], "inet": ["acct", "labl", "ptcl", "srvr"]}


def show(item: dict) -> None:
    print('keychain: "/Users/test/Library/Keychains/login.keychain-db"')
    print("version: 512")
    print(f'class: "{item["class"]}"')
    print("attributes:")
    for key in ATTRS[item["class"]]:
        value = item.get(key)
        tag = "0x00000007 " if key == "labl" else f'"{key}"'
        rendered = "<NULL>" if value is None else print_buffer(value.encode())
        print(f"    {tag}<blob>={rendered}")


def match(item: dict, cls: str, opts: dict) -> bool:
    keys = {"-s": "srvr" if cls == "inet" else "svce", "-a": "acct", "-D": "desc"}
    return item["class"] == cls and all(item.get(keys[k]) == v for k, v in opts.items() if k in keys)


def command(argv: list[str]) -> int:
    if os.environ.get("FAKE_SECURITY_LOCKED") == "1":
        return fail("SecKeychainItemCopyContent: User interaction is not allowed.", 1)
    name, rest = argv[0], argv[1:]
    items = load()
    if name == "add-generic-password":
        opts, _ = getopt.getopt(rest, "a:c:C:D:G:j:l:s:p:w:X:UAT:h")
        o = dict(opts)
        data = bytes.fromhex(o["-X"]) if "-X" in o else o.get("-w", "").encode()
        existing = [i for i in items if match(i, "genp", {"-s": o["-s"], "-a": o["-a"]})]
        if existing and "-U" not in o:
            return fail("SecKeychainItemCreateFromContent: The specified item already exists.", 45)
        item = existing[0] if existing else {"class": "genp"}
        item.update(
            {
                "svce": o["-s"],
                "acct": o["-a"],
                "desc": o.get("-D"),
                "labl": o.get("-l", o["-s"]),
                "icmt": o.get("-j"),
                "data": data.hex(),
            }
        )
        if not existing:
            items.append(item)
        save(items)
        return 0
    if name in ("find-generic-password", "find-internet-password", "delete-generic-password"):
        cls = "inet" if "internet" in name else "genp"
        opts, _ = getopt.getopt(rest, "ha:c:C:d:D:G:j:l:p:P:r:s:t:wg")
        o = dict(opts)
        found = [i for i in items if match(i, cls, o)]
        if not found:
            return fail(NOT_FOUND, 44)
        if name.startswith("delete"):
            items.remove(found[0])
            save(items)
            return 0
        data = bytes.fromhex(found[0]["data"])
        if "-w" in o:
            print(data.hex() if any(not (32 <= c <= 126) for c in data) else data.decode())
            return 0
        show(found[0])
        if "-g" in o:
            print("password: " + print_buffer(data), file=sys.stderr)
        return 0
    if name == "dump-keychain":
        for item in items:
            show(item)
        return 0
    if name == "default-keychain":
        print('    "/Users/test/Library/Keychains/login.keychain-db"')
        return 0
    return fail(f"unknown command {name}", 2)


def main() -> int:
    if ARGV_LOG:
        with open(ARGV_LOG, "a") as fh:
            fh.write(json.dumps(sys.argv[1:]) + "\n")
    if sys.argv[1:] == ["-i"]:
        rc = 0
        for line in sys.stdin:
            if ARGV_LOG:
                with open(ARGV_LOG + ".stdin", "a") as fh:
                    fh.write(line)
            rc = command(shlex.split(line))
            if rc:
                print(f"{shlex.split(line)[0]}: returned {rc}", file=sys.stderr)
        return rc
    return command(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
