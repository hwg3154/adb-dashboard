"""Wake-on-LAN: the one way to reach a TV that has gone to sleep.

A sleeping TV is off the network as far as adb is concerned - no port answers, so no key can
wake it. With networked standby enabled, its network card stays powered and watches for a
"magic packet": six 0xFF bytes followed by its own MAC address sixteen times. Nothing above the
card is involved, which is exactly why this works when adb cannot.

What this module will and will not do:
- the payload is fixed: a magic packet built from a validated MAC, nothing else
- it is sent only toward a device already in the registry - that device's own address and the
  broadcast addresses of its /24 - on the discard port
- the MAC comes from the server, never from the browser: the registry, or this machine's own
  ARP table for the device's address

The MAC has to be learned while the TV is awake, because the ARP table only knows the devices
this machine has recently talked to. `lookup_mac` is therefore called after a successful
command, and the result is kept in the registry for the next time the TV is asleep.

`is_awake` answers the other half of the question - whether a wake is needed at all - by
checking the one thing a launch depends on: whether the TV's adb port accepts a connection.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess

from .netguard import normalize_mac

#: The discard port. The network card inspects the frame rather than the port, but 9 is what
#: tools send to and what some cards filter on.
WOL_PORT = 9
_LIMITED_BROADCAST = "255.255.255.255"
_PROC_ARP = "/proc/net/arp"
_LOOKUP_TIMEOUT_SECONDS = 2.0
_MAX_OUTPUT_BYTES = 64 * 1024


def magic_packet(mac: str) -> bytes:
    """Build the 102-byte packet for one MAC. Raises ValueError for anything that is not one."""
    canonical = normalize_mac(mac)
    if not canonical:
        raise ValueError("not a usable MAC address")
    return b"\xff" * 6 + bytes.fromhex(canonical.replace(":", "")) * 16


def destinations(host: str) -> tuple[str, ...]:
    """Where to send: the device itself, its /24's broadcast, and the limited broadcast.

    Broadcasts are what Wake-on-LAN is designed around. The unicast copy is for a machine that
    cannot broadcast onto the TV's segment - one behind a NAT, say - but can still route to the
    TV's own address, which a card in networked standby may keep answering for.
    """
    address = _usable_address(host)
    if address is None:
        return ()
    network = ipaddress.ip_network(f"{address}/24", strict=False)
    return (str(address), str(network.broadcast_address), _LIMITED_BROADCAST)


def send(mac: str, host: str) -> int:
    """Send the magic packet for `mac` toward `host`. Returns how many sends succeeded.

    UDP is fire-and-forget: success means the packet left this machine, not that the TV heard
    it. Callers say "sent", never "woke".
    """
    packet = magic_packet(mac)
    targets = destinations(host)
    if not targets:
        return 0
    sent = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for target in targets:
            try:
                sock.sendto(packet, (target, WOL_PORT))
                sent += 1
            except OSError:
                continue
    finally:
        sock.close()
    return sent


def is_awake(host: str, port: int, timeout: float = 1.0) -> bool:
    """Whether the TV's adb port accepts a connection right now. Never raises.

    That is the question a launch depends on, so it is the one asked. ICMP would be the wrong
    question twice over: a TV in networked standby can keep answering ping while adb is down,
    and ping needs a privilege a locked-down container does not have.

    The connection is opened and closed without sending a byte - the same bare connect the
    discovery sweep makes.
    """
    address = _usable_address(host)
    if address is None or isinstance(port, bool) or not isinstance(port, int):
        return False
    if not 1 <= port <= 65535:
        return False
    try:
        with socket.create_connection((str(address), port), timeout=max(0.05, float(timeout))):
            return True
    except (OSError, ValueError):
        return False


def _usable_address(host: object) -> ipaddress.IPv4Address | None:
    """A private, non-loopback, non-link-local IPv4 address, or None: the only hosts this
    module will ever send a packet to or open a connection to."""
    if not isinstance(host, str):
        return None
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        return None
    if not address.is_private or address.is_loopback or address.is_link_local:
        return None
    return address


# ------------------------------------------------------------------------------ ARP lookup


def lookup_mac(host: str) -> str:
    """This machine's ARP entry for `host`, or ''. Never raises and never sends anything.

    Linux exposes the table as a file, so the common case - including a container on host
    networking - needs no binary and no privilege. Elsewhere `ip neigh`, then `arp -n`, are
    asked in turn. Only the entry for this exact address is used, so a router's MAC can never
    be mistaken for the TV's: an address that is not on this network simply has no entry.
    """
    try:
        address = str(ipaddress.IPv4Address(host))
    except (TypeError, ValueError):
        return ""

    try:
        with open(_PROC_ARP, "r", encoding="ascii", errors="replace") as handle:
            found = parse_proc_arp(handle.read(_MAX_OUTPUT_BYTES), address)
        if found:
            return found
    except OSError:
        pass

    for argv, parser in (
        (["ip", "neigh", "show", address], parse_ip_neigh),
        (["arp", "-n", address], parse_bsd_arp),
    ):
        binary = shutil.which(argv[0])
        if not binary:
            continue
        found = parser(_run([binary, *argv[1:]]), address)
        if found:
            return found
    return ""


def parse_proc_arp(text: str, address: str) -> str:
    """`/proc/net/arp`: IP, HW type, flags, HW address, mask, device. Flag 0x2 means resolved."""
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[0] != address:
            continue
        try:
            resolved = int(fields[2], 16) & 0x2
        except ValueError:
            continue
        if resolved:
            mac = normalize_mac(fields[3])
            if mac:
                return mac
    return ""


def parse_ip_neigh(text: str, address: str) -> str:
    """`ip neigh show ADDR`: `ADDR dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`.

    A STALE entry still names the right card, so it counts; a FAILED one has no `lladdr`.
    """
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != address or "lladdr" not in fields:
            continue
        index = fields.index("lladdr")
        if index + 1 < len(fields):
            mac = normalize_mac(fields[index + 1])
            if mac:
                return mac
    return ""


def parse_bsd_arp(text: str, address: str) -> str:
    """macOS / BSD `arp -n ADDR`: `? (ADDR) at d0:65:b3:27:38:b on en0 ifscope [ethernet]`.

    Octets can lose their leading zero there; `normalize_mac` puts it back.
    """
    needle = f"({address})"
    for line in text.splitlines():
        fields = line.split()
        if needle not in fields or "at" not in fields:
            continue
        index = fields.index("at")
        if index + 1 < len(fields):
            mac = normalize_mac(fields[index + 1])
            if mac:
                return mac
    return ""


def _run(argv: list[str]) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, validated address, no shell
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_LOOKUP_TIMEOUT_SECONDS,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (proc.stdout or b"")[:_MAX_OUTPUT_BYTES].decode("ascii", "replace")


__all__ = [
    "WOL_PORT",
    "destinations",
    "is_awake",
    "lookup_mac",
    "magic_packet",
    "parse_bsd_arp",
    "parse_ip_neigh",
    "parse_proc_arp",
    "send",
]
