"""The macOS backend against a fake `security` (no macOS runner exists for this repo)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from keychainlib.backends.macos import MacOSBackend, decode_buffer, parse_items
from keychainlib.errors import Locked, NotFound, UsageError
from keychainlib.refs import Ref

from .conftest import SECRET

FAKE = Path(__file__).with_name("fake_security.py")


@pytest.fixture
def mac(tmp_path, monkeypatch):
    tool = tmp_path / "security"
    tool.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    tool.chmod(0o755)
    monkeypatch.setenv("FAKE_SECURITY_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FAKE_SECURITY_ARGV_LOG", str(tmp_path / "argv.log"))
    backend = MacOSBackend(security=str(tool))
    backend.log = tmp_path / "argv.log"
    return backend


@pytest.mark.parametrize(
    "value",
    [SECRET.encode(), b"plain", b'quo"te', b"back\\slash", b"line\nbreak", b"\x00\xff", b" lead-space"],
)
def test_roundtrip_any_bytes(mac, value):
    ref = Ref("tg-cli", "bot-token")
    mac.set(ref, value, "Bot token", "prod")
    assert mac.get(ref) == value
    argv_text = mac.log.read_text()
    assert value.hex() not in argv_text  # the hex form goes through stdin only
    if len(value) > 4:
        assert value.decode("latin-1") not in argv_text


def test_metadata_list_and_update_preserves_label(mac):
    ref = Ref("tg-cli", "bot-token")
    mac.set(ref, b"one1", "Bot", "first")
    mac.set(ref, b"two2", None, None)
    info = mac.info(ref)
    assert (info.label, info.note) == ("Bot", "first")
    assert mac.get(ref) == b"two2"
    mac.set(Ref("x", "y"), b"zzzz", None, None)
    assert [str(i.ref) for i in mac.list()] == ["tg-cli/bot-token", "x/y"]
    assert [str(i.ref) for i in mac.list("x")] == ["x/y"]


def test_origin_is_kept_and_both_note_and_origin_can_be_cleared(mac):
    ref = Ref("site", "alex")
    mac.set(ref, b"pw-1", None, "note", "https://site.tld")
    mac.set(ref, b"pw-2", None, None)
    assert (mac.info(ref).note, mac.info(ref).origin) == ("note", "https://site.tld")
    mac.set(ref, b"pw-3", None, "", "")
    assert (mac.info(ref).note, mac.info(ref).origin) == ("", "")


def test_not_found_and_delete(mac):
    ref = Ref("a", "b")
    with pytest.raises(NotFound):
        mac.get(ref)
    mac.set(ref, b"vvvv", None, None)
    mac.delete(ref)
    with pytest.raises(NotFound):
        mac.delete(ref)


def test_locked_maps_to_exit_9(mac, monkeypatch):
    monkeypatch.setenv("FAKE_SECURITY_LOCKED", "1")
    with pytest.raises(Locked):
        mac.get(Ref("a", "b"))


def test_system_items(mac, tmp_path):
    state = [
        {
            "class": "inet",
            "srvr": "github.com",
            "acct": "alex@example.com",
            "labl": "github.com",
            "ptcl": "htps",
            "data": b"web-pass".hex(),
        },
        {
            "class": "genp",
            "svce": "Wi-Fi",
            "acct": "Home Net",
            "desc": "AirPort network password",
            "labl": "Home Net",
            "icmt": None,
            "data": b"wifi-pass".hex(),
        },
    ]
    (tmp_path / "state.json").write_text(json.dumps(state))
    items = mac.system_list({})
    assert [i.id for i in items] == ["genp:Wi-Fi/Home%20Net", "inet:github.com/alex@example.com"]
    assert mac.system_get("inet:github.com/alex@example.com") == b"web-pass"
    assert mac.system_get("genp:Wi-Fi/Home%20Net") == b"wifi-pass"
    assert mac.system_list({"srvr": "github.com"})[0].label == "github.com"


def test_rejects_quotes_in_label(mac):
    with pytest.raises(UsageError):
        mac.set(Ref("a", "b"), b"vvvv", 'bad"label', None)


def test_too_large(mac):
    with pytest.raises(UsageError):
        mac.set(Ref("a", "b"), b"x" * 3000, None, None)


def test_decode_buffer_formats():
    assert decode_buffer('"abc"') == b"abc"
    assert decode_buffer('"a"b"') == b'a"b'
    assert decode_buffer('0x615C62  "a\\134b"') == b"a\\b"
    assert decode_buffer("0x00FF ") == b"\x00\xff"
    assert decode_buffer("<NULL>") is None


def test_parse_items_label_tag():
    dump = 'class: "genp"\nattributes:\n    0x00000007 <blob>="L"\n    "svce"<blob>="s"\n'
    assert parse_items(dump) == [{"class": "genp", "attrs": {"labl": "L", "svce": "s"}}]


def test_system_get_refuses_own_items(mac):
    mac.set(Ref("tg-cli", "bot-token"), b"vvvv", None, None)
    assert mac.system_list({}) == []  # our items are not "system" items
    with pytest.raises(UsageError):
        mac.system_get("genp:tg-cli/bot-token")


def test_password_text_cannot_fake_an_error(mac):
    ref = Ref("a", "b")
    tricky = b"The specified item could not be found -25308 canceled"
    mac.set(ref, tricky, None, None)
    assert mac.get(ref) == tricky


def test_store_cannot_inject_options():
    with pytest.raises(UsageError):
        MacOSBackend(keychain="-A")


def test_default_security_path_is_fixed():
    assert MacOSBackend().security == "/usr/bin/security"


def test_set_refuses_to_overwrite_foreign_item(mac, tmp_path):
    state = [{"class": "genp", "svce": "github.com", "acct": "alex", "desc": "application password",
              "labl": "x", "icmt": None, "data": b"theirs".hex()}]
    (tmp_path / "state.json").write_text(json.dumps(state))
    with pytest.raises(UsageError):
        mac.set(Ref("github.com", "alex"), b"mine-value", None, None)
    assert json.loads((tmp_path / "state.json").read_text())[0]["data"] == b"theirs".hex()


def test_line_limit_counts_bytes(mac):
    with pytest.raises(UsageError):
        mac.set(Ref("a", "b"), b"x" * 1700, "я" * 200, "ж" * 200)
