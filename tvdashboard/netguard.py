"""Target validation for device addresses.

Anything coming from the browser that names a network target is checked here before a socket is
opened: IPv4 literal only, RFC1918 only, fixed ports only. No hostnames, no DNS, no redirects.

A browser can therefore never point this appliance at an internal service, a cloud metadata
endpoint, or anything outside the configured LAN ranges.
"""

from __future__ import annotations

import ipaddress
import re

from .config import DEFAULT_ALLOWED_CIDRS, DEVICE_PORTS

#: IPv4 literals only: four dotted octets, no hostname, no userinfo, no port in the host part.
_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_TARGET_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$")
_PAIR_CODE_RE = re.compile(r"^\d{6,10}$")

#: Android 11+ shows a *pairing* port next to the code, and it is a fresh random one each
#: time - not 5555. Pairing against the connect port simply fails, so the pairing address
#: gets its own check: same RFC1918 host rule, any ephemeral port.
PAIR_PORT_MIN = 1024
PAIR_PORT_MAX = 65535

_REJECTED_NETS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",        # "this host" / unspecified
        "100.64.0.0/10",    # carrier-grade NAT
        "127.0.0.0/8",      # loopback
        "169.254.0.0/16",   # link-local, includes 169.254.169.254
        "224.0.0.0/4",      # multicast
        "240.0.0.0/4",      # reserved / broadcast
    )
)
_RFC1918: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(net) for net in DEFAULT_ALLOWED_CIDRS
)


class TargetRejected(ValueError):
    """Raised when a target string is not a usable, in-scope device address."""


def normalize_target(value: object, allowed_cidrs: tuple[str, ...], ports: tuple[int, ...]) -> str:
    """Validate `host[:port]` and return the canonical `host:port` string.

    Rejects: non-strings, empty strings, hostnames, IPv6, anything outside the allowed CIDRs,
    loopback / link-local / multicast / unspecified addresses, and non-device ports.
    """
    if not isinstance(value, str):
        raise TargetRejected("target must be a string")
    raw = value.strip()
    if not raw or len(raw) > 64:
        raise TargetRejected("target has the wrong shape")

    if "://" in raw or "@" in raw or "/" in raw:
        raise TargetRejected("target must not contain a URL")

    match = _TARGET_RE.match(raw)
    host, port_text = (match.group(1), match.group(2)) if match else (raw, "")
    if not _HOST_RE.match(host):
        raise TargetRejected("only dotted IPv4 targets are allowed")

    try:
        port = int(port_text) if port_text else min(ports)
    except (TypeError, ValueError) as exc:
        raise TargetRejected("target has the wrong shape") from exc

    if port not in ports:
        raise TargetRejected("port is not an adb device port")

    try:
        address = ipaddress.IPv4Address(host)
    except (TypeError, ValueError) as exc:
        raise TargetRejected("only dotted IPv4 targets are allowed") from exc

    if _is_excluded(address):
        raise TargetRejected("target is not a usable unicast address")
    if not _in_allowed_nets(address, allowed_cidrs):
        raise TargetRejected("target is outside the allowed network")

    return f"{address}:{port}"


def normalize_pair_target(value: object, allowed_cidrs: tuple[str, ...]) -> tuple[str, int]:
    """Validate the `host:port` the TV shows in its pairing dialog.

    The host is held to exactly the same rule as any other target - dotted IPv4, RFC1918,
    nothing loopback or link-local - so this widens the port and nothing else.
    """
    if not isinstance(value, str):
        raise TargetRejected("pairing address must be a string")
    raw = value.strip()
    if not raw or len(raw) > 64:
        raise TargetRejected("pairing address has the wrong shape")
    if "://" in raw or "@" in raw or "/" in raw:
        raise TargetRejected("pairing address must not contain a URL")

    match = _TARGET_RE.match(raw)
    if not match:
        raise TargetRejected("pairing address must be host:port")
    host, port_text = match.group(1), match.group(2)
    if not _HOST_RE.match(host):
        raise TargetRejected("only dotted IPv4 targets are allowed")

    try:
        port = int(port_text)
    except (TypeError, ValueError) as exc:
        raise TargetRejected("pairing port is not a number") from exc
    if not PAIR_PORT_MIN <= port <= PAIR_PORT_MAX:
        raise TargetRejected("pairing port is out of range")

    try:
        address = ipaddress.IPv4Address(host)
    except (TypeError, ValueError) as exc:
        raise TargetRejected("only dotted IPv4 targets are allowed") from exc
    if _is_excluded(address):
        raise TargetRejected("target is not a usable unicast address")
    if not _in_allowed_nets(address, allowed_cidrs):
        raise TargetRejected("target is outside the allowed network")
    return str(address), port


def candidate_id(value: object) -> str:
    """Validate an opaque candidate id handed back by the wizard."""
    if not isinstance(value, str):
        raise TargetRejected("candidate id is missing")
    raw = value.strip().lower()
    if len(raw) != 32 or any(char not in "0123456789abcdef" for char in raw):
        raise TargetRejected("candidate id is not valid")
    return raw


def validate_pair_code(value: object) -> str:
    """Validate a pairing code (digits only, as shown by the Android TV dialog)."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TargetRejected("pairing code must be a string")
    raw = value.strip()
    if not raw:
        return ""
    if not _PAIR_CODE_RE.match(raw):
        raise TargetRejected("pairing code must be 6-10 digits")
    return raw


def _is_excluded(address: ipaddress.IPv4Address) -> bool:
    return bool(
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.packed == b"\x00" * 4
        or any(address in net for net in _REJECTED_NETS)
    )


def _in_allowed_nets(address: ipaddress.IPv4Address, allowed_cidrs: tuple[str, ...]) -> bool:
    for cidr in _RFC1918:
        if address in cidr:
            return True
    for chunk in allowed_cidrs:
        try:
            net = ipaddress.ip_network(chunk, strict=False)
        except (TypeError, ValueError):
            continue
        if net.version == 4 and address in net:
            return True
    return False
