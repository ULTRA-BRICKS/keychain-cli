"""macOS backend: the login keychain through Apple's `security` tool.

Secret values never touch argv. Writes go through `security -i`, which reads the command line
from stdin, with the value hex-encoded (`-X`) so no quoting can break or truncate it. Reads use
`-g`, which prints ``password: `` on stderr either as ``"ascii"`` (only when every byte is
printable and not a backslash) or as ``0xHEX`` followed by an optional ascii rendering — both
are unambiguous, unlike `-w`, which prints hex or raw text depending on content.

Our items are generic passwords whose kind (``-D``) is ``keychain-cli``; service and account
are the ref's halves. Items created by `security` trust `/usr/bin/security` in their ACL, so any
same-user process that runs `security` can read them without a dialog — the usual property of
CLI-managed keychain items. Items other apps created (Safari, Wi-Fi) trust those apps instead,
so reading one through `system get` raises the macOS "allow access" dialog, which cannot appear
in a headless SSH session. iCloud Keychain (the Passwords app) items are not reachable from
`security` at all.

Not verified on a real Mac by this project's CI (no macOS runner); covered by tests that run
this module against a fake `security` implementing the documented behavior.
"""

from __future__ import annotations

import re
import subprocess
from urllib.parse import quote, unquote

from ..errors import BackendError, Locked, MissingDependency, NotFound, PolicyDenied, UsageError
from ..refs import Ref
from . import ItemInfo, SystemItem, safe_attributes

KIND = "keychain-cli"
SECURITY = "/usr/bin/security"
MAX_LINE = 4000  # `security -i` reads lines into a 4096-byte buffer
_ATTR_RE = re.compile(r'^\s+(?P<tag>"[^"]*"|0x[0-9A-Fa-f]+)\s*(?:"[^"]*")?\s*<(?P<fmt>[^>]*)>=(?P<val>.*)$')
_NAMED_TAGS = {"0x00000007": "labl", "0x00000008": "gena"}
_UNSAFE_ARG = re.compile(r'["\\\n\r\x00]')


def decode_buffer(text: str) -> bytes | None:
    """Decode one value printed by security's print_buffer: ``<NULL>``, ``"ascii"``,
    ``0xHEX`` or ``0xHEX  "ascii"``."""
    text = text.strip()
    if text in ("", "<NULL>"):
        return None if text == "<NULL>" else b""
    if text.startswith("0x"):
        return bytes.fromhex(text[2:].split()[0])
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text[1:-1].encode("latin-1")
    raise BackendError("unexpected output from `security`", why="unparseable value")


def parse_items(dump: str) -> list[dict]:
    """Parse `security dump-keychain` / `find-*-password` stdout into attribute dicts."""
    items: list[dict] = []
    current: dict | None = None
    for line in dump.splitlines():
        if line.startswith("class: "):
            raw = decode_buffer(line[len("class: ") :]) or b""
            current = {"class": raw.decode("latin-1"), "attrs": {}}
            items.append(current)
            continue
        m = _ATTR_RE.match(line)
        if m and current is not None:
            tag = m.group("tag")
            tag = tag.strip('"') if tag.startswith('"') else _NAMED_TAGS.get(tag.lower(), tag)
            value = decode_buffer(m.group("val"))
            if value is not None and m.group("fmt") in ("blob", "string"):
                current["attrs"][tag] = value.decode("utf-8", "replace").rstrip("\x00")
            elif value is not None and m.group("fmt") == "uint32" and tag in ("ptcl", "port"):
                # An internet password's site: `"ptcl"<uint32>="htps"`, `"port"<uint32>=0x000001BB`.
                current["attrs"][tag] = (
                    value.decode("latin-1") if tag == "ptcl" else str(int.from_bytes(value, "big"))
                )
    return items


def _password_from_stderr(stderr: str) -> bytes:
    for line in stderr.splitlines():
        if line.startswith("password: ") or line == "password:":
            value = decode_buffer(line[len("password:") :])
            return value or b""
    raise BackendError("`security` returned no password line")


def _q(value: str) -> str:
    if _UNSAFE_ARG.search(value):
        raise UsageError("labels and notes on macOS cannot contain quotes, backslashes or newlines")
    return f'"{value}"'


class MacOSBackend:
    name = "macos-keychain"

    def __init__(self, keychain: str | None = None, security: str = SECURITY) -> None:
        if keychain is not None and (keychain.startswith("-") or _UNSAFE_ARG.search(keychain)):
            # it is appended as a positional argument; a leading '-' would become an option
            raise UsageError("invalid --store for macOS: give a keychain file path or name")
        self.keychain = keychain
        # A fixed path, never a PATH lookup: whatever runs as `security` receives every value.
        self.security = security

    def _run(
        self, args: list[str], stdin: bytes | None = None, what: str = ""
    ) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(
                [self.security, *args], input=stdin, capture_output=True, timeout=300, check=False
            )
        except FileNotFoundError as exc:
            raise MissingDependency(
                "the macOS `security` tool is missing", fix="it ships with macOS at /usr/bin/security"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise Locked(f"{what}: the keychain did not answer (a dialog waiting?)") from exc
        # Classify on stderr without the `password:` line that -g prints there, so a password
        # can neither trip a pattern nor end up in an error message.
        err = "\n".join(
            line
            for line in proc.stderr.decode("utf-8", "replace").splitlines()
            if not line.startswith("password:")
        )
        if proc.returncode == 44 or "could not be found" in err:
            raise NotFound(f"{what}: not found")
        if "User interaction is not allowed" in err or "-25308" in err:
            raise Locked(
                f"{what}: the keychain is locked or needs a dialog that cannot be shown here (SSH session?)",
                fix="run `keychain unlock` (security unlock-keychain), then retry",
            )
        if "-128" in err or "canceled" in err.lower():
            raise PolicyDenied(f"{what}: access was declined in the macOS dialog")
        if proc.returncode != 0:
            first = err.strip().splitlines()[-1] if err.strip() else f"exit {proc.returncode}"
            raise BackendError(f"{what}: `security` failed", why=first)
        return proc

    def _kc(self) -> list[str]:
        return [self.keychain] if self.keychain else []

    def get(self, ref: Ref) -> bytes:
        proc = self._run(
            ["find-generic-password", "-s", ref.service, "-a", ref.account, "-D", KIND, "-g", *self._kc()],
            what=str(ref),
        )
        self._require_exact(proc, ref)
        return _password_from_stderr(proc.stderr.decode("utf-8", "replace"))

    @staticmethod
    def _require_exact(proc: subprocess.CompletedProcess, ref: Ref) -> dict:
        """`security` matching is the keychain's; re-check service/account/kind exactly so a
        loosely matched item from another namespace is never returned."""
        items = parse_items(proc.stdout.decode("utf-8", "replace"))
        attrs = items[0]["attrs"] if items else {}
        if (attrs.get("svce"), attrs.get("acct"), attrs.get("desc")) != (ref.service, ref.account, KIND):
            raise NotFound(f"no secret {ref}")
        return attrs

    def set(
        self, ref: Ref, value: bytes, label: str | None, note: str | None, origin: str | None = None
    ) -> None:
        try:
            old = self.info(ref)
        except NotFound:
            old = None
            # `-U` matches by service/account only: never let it overwrite another app's item
            try:
                self._run(
                    ["find-generic-password", "-s", ref.service, "-a", ref.account, *self._kc()],
                    what=str(ref),
                )
            except NotFound:
                pass
            else:
                raise UsageError(
                    f"another app's keychain item already uses {ref}", fix="pick another account name"
                )
        label = label if label is not None else (old.label if old else str(ref))
        note = note if note is not None else (old.note if old else "")
        origin = origin if origin is not None else (old.origin if old else "")
        parts = [
            "add-generic-password",
            "-U",
            "-s",
            _q(ref.service),
            "-a",
            _q(ref.account),
            "-D",
            _q(KIND),
            "-l",
            _q(label),
        ]
        # `-U` keeps attributes it is not given, so clearing a note or an origin writes an
        # explicit empty value. The generic attribute (`gena`) holds the origin.
        if note or (old and old.note):
            parts += ["-j", _q(note)]
        if origin or (old and old.origin):
            parts += ["-G", _q(origin)]
        parts += ["-X", bytes(value).hex()]
        if self.keychain:
            parts.append(_q(self.keychain))
        line = " ".join(parts) + "\n"
        if len(line.encode("utf-8")) > MAX_LINE:
            raise UsageError(
                "secret too large for the macOS keychain path (about 1.9 KB max)",
                why="`security -i` reads one command line of at most 4096 bytes",
            )
        proc = self._run(["-i"], stdin=line.encode("utf-8"), what=f"storing {ref}")
        err = proc.stderr.decode("utf-8", "replace")
        if "security: " in err or ": returned " in err:
            raise BackendError(f"storing {ref} failed", why=err.strip().splitlines()[-1])

    def delete(self, ref: Ref) -> None:
        self.info(ref)  # exact match first: `security` deletes the first item it matches
        self._run(
            ["delete-generic-password", "-s", ref.service, "-a", ref.account, "-D", KIND, *self._kc()],
            what=str(ref),
        )

    def info(self, ref: Ref) -> ItemInfo:
        proc = self._run(
            ["find-generic-password", "-s", ref.service, "-a", ref.account, "-D", KIND, *self._kc()],
            what=str(ref),
        )
        return self._to_info(self._require_exact(proc, ref)) or ItemInfo(ref)

    @staticmethod
    def _to_info(attrs: dict) -> ItemInfo | None:
        if attrs.get("desc") != KIND or "svce" not in attrs or "acct" not in attrs:
            return None
        try:
            ref = Ref(attrs["svce"], attrs["acct"])
        except Exception:  # noqa: BLE001
            return None
        return ItemInfo(
            ref=ref, label=attrs.get("labl", ""), note=attrs.get("icmt", ""), origin=attrs.get("gena", "")
        )

    def _dump(self) -> list[dict]:
        proc = self._run(["dump-keychain", *self._kc()], what="listing the keychain")
        return parse_items(proc.stdout.decode("utf-8", "replace"))

    def list(self, service: str | None = None) -> list[ItemInfo]:
        out = []
        for item in self._dump():
            if item["class"] != "genp":
                continue
            info = self._to_info(item["attrs"])
            if info and (service is None or info.ref.service == service):
                out.append(info)
        return sorted(out, key=lambda i: str(i.ref))

    @staticmethod
    def _system_id(item: dict) -> str | None:
        attrs = item["attrs"]
        if item["class"] == "inet":
            host, acct = attrs.get("srvr", ""), attrs.get("acct", "")
            kind = "inet"
        elif item["class"] == "genp":
            if attrs.get("desc") == KIND:
                return None
            host, acct = attrs.get("svce", ""), attrs.get("acct", "")
            kind = "genp"
        else:
            return None
        return f"{kind}:{quote(host, safe='@.-_+:')}/{quote(acct, safe='@.-_+:')}"

    def system_list(self, query: dict[str, str]) -> list[SystemItem]:
        out = []
        for item in self._dump():
            ident = self._system_id(item)
            if ident is None:
                continue
            attrs = safe_attributes(item["attrs"])
            if not all(attrs.get(k) == v for k, v in query.items()):
                continue
            out.append(
                SystemItem(
                    id=ident, label=item["attrs"].get("labl", ""), kind=item["class"], attributes=attrs
                )
            )
        return sorted(out, key=lambda s: s.id)

    def system_info(self, ident: str) -> SystemItem:
        for item in self.system_list({}):
            if item.id == ident:
                return item
        raise NotFound(f"no system item {ident}", fix="ids come from `keychain system list`")

    def system_get(self, ident: str) -> bytes:
        kind, _, rest = ident.partition(":")
        host, sep, acct = rest.partition("/")
        if kind not in ("inet", "genp") or not sep:
            raise UsageError(
                f"invalid macOS system item id {ident!r}", fix="use an id from `keychain system list`"
            )
        cmd = "find-internet-password" if kind == "inet" else "find-generic-password"
        proc = self._run(
            [cmd, "-s", unquote(host), "-a", unquote(acct), "-g", *self._kc()], what=f"system:{ident}"
        )
        found = parse_items(proc.stdout.decode("utf-8", "replace"))
        if found and found[0]["attrs"].get("desc") == KIND:
            # Reading our own item by id would sidestep the namespace check on its ref.
            raise UsageError(f"system:{ident} is a keychain-cli item; address it by its service/account ref")
        return _password_from_stderr(proc.stderr.decode("utf-8", "replace"))

    def ensure_unlocked(self, what: str, system_id: str | None = None) -> None:
        """Nothing to do: `security` lists item attributes of a locked keychain and asks for the
        unlock only when a secret is read."""

    def unlock(self, create: bool = False) -> str:
        if create:
            raise UsageError("--create is Linux-only; macOS always has a login keychain")
        # `security unlock-keychain` asks for the password on the controlling TTY itself;
        # inheriting stdio keeps the password out of this process entirely.
        try:
            rc = subprocess.call([self.security, "unlock-keychain", *self._kc()])
        except FileNotFoundError as exc:
            raise MissingDependency("the macOS `security` tool is missing") from exc
        if rc != 0:
            raise Locked("the keychain did not unlock", why="wrong password?")
        return "keychain unlocked"

    def status(self) -> dict:
        out: dict = {"backend": self.name, "security": self.security, "keychain": self.keychain}
        try:
            proc = self._run(["default-keychain"], what="default keychain")
            out["default"] = proc.stdout.decode("utf-8", "replace").strip().strip('"')
            info = self._run(["show-keychain-info", *self._kc()], what="keychain info")
            out["info"] = (info.stdout + info.stderr).decode("utf-8", "replace").strip()
        except Exception as exc:  # noqa: BLE001 - doctor reports, never raises
            out["error"] = getattr(exc, "what", str(exc))
        return out
