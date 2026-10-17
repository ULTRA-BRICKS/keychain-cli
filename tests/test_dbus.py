"""The stdlib D-Bus marshaller against hand-checked wire bytes and round trips."""

from __future__ import annotations

import struct

import pytest

from keychainlib.backends.dbus import (
    METHOD_CALL,
    Message,
    Variant,
    decode_message,
    encode_message,
    marshal,
    message_length,
    split_signature,
    unmarshal,
)


def test_split_signature():
    assert split_signature("sa{sv}o(oayays)ab") == ["s", "a{sv}", "o", "(oayays)", "ab"]
    with pytest.raises(ValueError):
        split_signature("z")


def test_string_wire_format():
    assert marshal("s", ["ab"]) == struct.pack("<I", 2) + b"ab\0"
    assert marshal("ys", [1, "a"]) == b"\x01\0\0\0" + struct.pack("<I", 1) + b"a\0"


def test_dict_alignment():
    # array length excludes the padding before the first 8-aligned dict entry
    data = marshal("a{ss}", [{"k": "v"}])
    assert struct.unpack_from("<I", data)[0] == len(data) - 8
    assert unmarshal("a{ss}", data) == [{"k": "v"}]


@pytest.mark.parametrize(
    "sig,values",
    [
        ("a{ss}", [{"xdg:schema": "x", "service": "tg-cli", "account": "üñí"}]),
        ("(oayays)", [("/s/1", b"", "\x00\xffbin".encode("latin-1"), "text/plain")]),
        (
            "a{sv}(oayays)b",
            [
                {"a.Label": Variant("s", "L"), "a.Attributes": Variant("a{ss}", {"k": "v"})},
                ("/s", b"", b"secret", "t"),
                True,
            ],
        ),
        ("aob", [["/a", "/b/c"], False]),
        ("a{o(oayays)}", [{"/i/1": ("/s", b"", b"v", "t")}]),
        ("xtdqn", [-5, 2**63, 1.5, 65535, -2]),
    ],
)
def test_roundtrip(sig, values):
    decoded = unmarshal(sig, marshal(sig, values))
    expected = [
        {k: (v.value if isinstance(v, Variant) else v) for k, v in x.items()} if isinstance(x, dict) else x
        for x in values
    ]
    assert decoded == expected


def test_message_roundtrip_and_length():
    msg = Message(METHOD_CALL, 9, {1: "/org/x", 2: "a.b", 3: "M", 6: "dest"}, ["s", Variant("s", "")])
    raw = encode_message(msg, "sv")
    assert message_length(raw[:16]) == len(raw)
    back = decode_message(raw)
    assert (back.serial, back.member, back.path, back.body) == (9, "M", "/org/x", ["s", ""])


def test_big_endian_decode():
    body = struct.pack(">I", 2) + b"hi\0"
    fields = b"\x08\x01g\x00\x01s\x00"  # one (SIGNATURE, v=g "s") entry, 7 bytes
    header = b"B\x02\x00\x01" + struct.pack(">II", len(body), 3) + struct.pack(">I", len(fields)) + fields
    header += b"\x00" * (-len(header) % 8)
    msg = decode_message(header + body)
    assert msg.body == ["hi"] and msg.serial == 3


def test_parser_rejects_hostile_input():
    from keychainlib.backends.dbus import DBusConnectionError

    with pytest.raises(ValueError):
        split_signature("a()")
    with pytest.raises(ValueError):
        split_signature("(s")
    with pytest.raises(DBusConnectionError):
        unmarshal("s", struct.pack("<I", 100) + b"short\0")  # length beyond the data
    with pytest.raises(DBusConnectionError):
        unmarshal("s", struct.pack("<I", 2) + b"abc")  # no NUL terminator


def test_peer_uid_check_accepts_own_socket():
    import socket

    from keychainlib.backends.dbus import _check_peer_uid

    a, b = socket.socketpair()
    try:
        _check_peer_uid(a)  # same process, same uid: accepted
    finally:
        a.close()
        b.close()
