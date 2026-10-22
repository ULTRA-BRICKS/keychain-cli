"""Web origins for `keychain fill`: which page may receive which credential.

A credential is bound to an origin (``https://site.tld``). A frame may receive it when:

- its scheme is https (plain http only for loopback hosts with ``KEYCHAIN_FILL_TEST=1``);
- its scheme and port equal the credential's, and its host is the credential's host or a
  subdomain of it (``login.site.tld`` for ``site.tld``);
- the caller's ``fill`` grant names the frame's origin (a glob such as
  ``https://*.site.tld``), so a subdomain is reachable only when the human allowed it;
- ``--origin``, when given, equals the frame's origin (it narrows, never widens).

There is no Public Suffix List here (the stdlib has none, and a vendored copy goes stale).
Instead of "same registrable domain" the rule is "same host, or a subdomain the human listed",
which is stricter: ``evil.github.io`` never matches ``github.io`` unless a grant says so.
"""

from __future__ import annotations

import ipaddress
import os
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import PolicyDenied, UsageError

DEFAULT_PORTS = {"https": 443, "http": 80}
LOOPBACK_NAMES = ("localhost",)


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = DEFAULT_PORTS.get(self.scheme)
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")

    @property
    def loopback(self) -> bool:
        if self.host in LOOPBACK_NAMES or self.host.endswith(".localhost"):
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False


def _punycode(label: str) -> str:
    """One internationalized label in punycode. Python's codec is IDNA2003, while browsers use
    UTS-46, and the two differ on some characters (IDNA2003 maps ``ß`` to ``ss``, ``ς`` to
    ``σ`` and drops joiners): ``faß.de`` would become ``fass.de``, another registrable domain.
    A label that does not survive the round trip unchanged is refused instead of guessed."""
    label = unicodedata.normalize("NFC", label)
    encoded = label.encode("idna").decode("ascii")
    if encoded.encode("ascii").decode("idna") != label:
        raise UnicodeError(f"the host label {label!r} has no unambiguous punycode form")
    return encoded


def _ascii_host(host: str) -> str:
    """Lowercase, no trailing dot, internationalized labels in punycode (``xn--…``), the form
    the browser reports frame URLs in. A ``*`` label (in a grant glob) is kept."""
    labels = host.lower().rstrip(".").split(".")
    return ".".join(label if label.isascii() or "*" in label else _punycode(label) for label in labels)


def parse_origin(url: str) -> Origin | None:
    """The origin of an http(s) URL; None for anything else (about:blank, data:, chrome:)."""
    try:
        parts = urlsplit(url)
        port = parts.port
        host = _ascii_host(parts.hostname or "")
    except ValueError:  # a bad port, or an IDN label punycode rejects (UnicodeError)
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not host:
        return None
    return Origin(scheme, host, port or DEFAULT_PORTS[scheme])


def normalize_origin_pattern(text: str) -> str:
    """A `fill` grant glob in the form page origins are matched in: lowercase scheme and host,
    punycode labels, no trailing slash, no default port (``https://GitHub.com:443/`` becomes
    ``https://github.com``). Globs stay globs: ``https://*.site.tld``."""
    scheme, sep, hostport = text.strip().partition("://")
    hostport = hostport.rstrip("/")
    scheme = scheme.lower()
    if not sep or not hostport or "/" in hostport or "@" in hostport or not scheme:
        raise UsageError(
            f"fill grant {text!r} is not an origin glob",
            fix='write scheme://host[:port], e.g. fill = ["https://github.com", "https://*.site.tld"]',
        )
    host, port = hostport, ""
    if ":" in hostport and not hostport.endswith("]"):
        host, _, port = hostport.rpartition(":")
    if port == str(DEFAULT_PORTS.get(scheme)):
        port = ""
    try:
        host = host if host.startswith("[") else _ascii_host(host)
    except UnicodeError as exc:
        raise UsageError(f"fill grant {text!r} has an invalid host name") from exc
    # An IPv6 literal's brackets would be a character class to fnmatch: match them literally.
    host = host.replace("[", "\0").replace("]", "[]]").replace("\0", "[[]")
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def normalize_origin(text: str) -> str:
    """Validate a user-given origin (``keychain set --origin``, ``fill --origin``)."""
    origin = parse_origin(text)
    try:
        parts = urlsplit(text)
    except ValueError:
        parts = None
    if origin is None or parts is None or "@" in parts.netloc:
        raise UsageError(
            "an origin is https://host[:port]", fix="e.g. --origin https://github.com"
        )
    return str(origin)


def fill_test_mode() -> bool:
    return os.environ.get("KEYCHAIN_FILL_TEST") == "1"


def check_scheme(frame: Origin | None, url_for_message: str = "") -> Origin:
    if frame is None:
        raise PolicyDenied(
            "the field is not on a web page (no http/https origin)",
            why=f"frame URL scheme: {url_for_message.split(':', 1)[0] or '?'}",
        )
    if frame.scheme == "https":
        return frame
    if frame.loopback and fill_test_mode():
        return frame
    raise PolicyDenied(
        f"refusing to fill a credential into {frame}: not https",
        why="a credential typed into a plain-http page can be read on the network",
    )


def binds(record: Origin, frame: Origin, subdomains: bool = True) -> bool:
    """Does a credential for ``record`` belong on a page at ``frame``? ``subdomains=False`` (a
    caller with no fill grant to name them, i.e. `user`) demands the exact host."""
    if (record.scheme, record.port) != (frame.scheme, frame.port):
        return False
    return frame.host == record.host or (subdomains and frame.host.endswith("." + record.host))
