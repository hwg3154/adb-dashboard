"""Find the TV on the local network.

Two cheap, honest techniques, both bounded:
1. a UDP broadcast probe, so a TV that answers a discovery query identifies itself
2. a TCP sweep of `device_ports` across the local /24, so a TV with "adb over network"
   enabled is found even when it never answers a probe

Discovery is capped to one /24, and every host is re-checked against the SSRF guard before it
becomes a candidate. A candidate is only trusted after it has answered for its `ro.product.*`
properties, which is what separates "a TV" from "something is listening".

mDNS is deliberately not implemented: it needs a resolver, it is unreliable inside containers,
and a bounded sweep finds the same devices.

See `docs/design.md` §7 for the wizard flow and §10 for the Docker/NAT limitation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass

from . import adb, registry
from .config import Config

#: One probe per sweep. The payload is a fixed constant, never user input.
UDP_PROBE = b"TV-DASHBOARD-DISCOVER-v1"
UDP_DISCOVERY_PORT = 5678
_BROADCAST_ADDR = "255.255.255.255"

#: Seed address used only to discover which local network we are on. Nothing is sent to it.
_PROBE_HOST = "8.8.8.8"
_PROBE_PORT = 53

#: Properties that prove a host is an Android device, in the order we read them.
_PROPS = ("ro.product.manufacturer", "ro.product.model", "ro.product.cpu.abi")

_HOST_OCTET_MIN = 1
_HOST_OCTET_MAX = 254


@dataclass(frozen=True)
class DiscoveredHost:
    """A host that answered discovery. `verified` is the only thing the wizard trusts."""

    host: str
    port: int
    source: str
    props: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        return len(self.props) == len(_PROPS) and all(bool(item) for item in self.props)

    @property
    def score(self) -> int:
        if self.verified:
            return 100
        if self.source == "broadcast":
            return 40
        return 20

    @property
    def model(self) -> str:
        """`_PROPS` is (manufacturer, model, abi); the label wants the model, not the vendor."""
        if len(self.props) >= 2 and self.props[1]:
            return self.props[1]
        return self.props[0] if self.props else ""

    def target(self) -> str:
        return f"{self.host}:{self.port}"

    def candidate(self) -> registry.Candidate:
        """Project into the registry's candidate shape, with a server-assigned opaque id."""
        return registry.Candidate(
            id=registry.candidate_key(self.host, self.port),
            host=self.host,
            port=self.port,
            score=self.score,
            added_at=int(time.time()),
            model=self.model,
        )


def discover(config: Config) -> list[registry.Candidate]:
    """Find candidate devices, each with an opaque id. Hosts and ports never leave the server.

    The browser receives only `id`, `model` and `score`, and answers with that id. It never
    gets to name a host or a port, so it cannot aim this appliance at anything else.
    """
    seeds = _local_subnets(config)
    hosts = _seed_hosts(seeds, config)
    found = _sweep(hosts, config)
    return [item.candidate() for item in found]


# ------------------------------------------------------------------------------- discovery


def _local_subnets(config: Config) -> list[tuple[ipaddress.IPv4Network, int]]:
    """Learn which /24 to sweep. The unconnected UDP socket is the trick: it reports the
    source address the OS would use for the LAN, which tells us the network without sending.

    Returns networks, because that is what `_seed_hosts` expands.
    """
    endpoints: list[tuple[ipaddress.IPv4Network, int]] = []
    seed: socket.socket | None = None
    try:
        seed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        seed.connect((_PROBE_HOST, _PROBE_PORT))
        local = seed.getsockname()[0]
        if isinstance(local, str) and _usable(local, config):
            endpoints.append((_slash24(local), 0))
    except OSError:
        pass
    finally:
        if seed is not None:
            seed.close()

    for host in _broadcast_replies(config):
        network = _slash24(host)
        if network is not None and all(network != known for known, _ in endpoints):
            endpoints.append((network, 0))
    return [(network, port) for network, port in endpoints if network is not None]


def _broadcast_replies(config: Config) -> list[str]:
    """Ask for a reply on the discovery port. Nothing on a TV is obliged to answer, so this
    only ever adds a network the routing table did not already reveal."""
    hosts: list[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(max(0.05, config.discover_timeout_seconds))
    try:
        sock.sendto(UDP_PROBE, (_BROADCAST_ADDR, UDP_DISCOVERY_PORT))
        while len(hosts) < _MAX_BROADCAST_REPLIES:
            data, addr = sock.recvfrom(256)
            host = addr[0] if isinstance(addr, tuple) and isinstance(addr[0], str) else ""
            if data and host and _usable(host, config) and host not in hosts:
                hosts.append(host)
    except OSError:
        pass
    finally:
        sock.close()
    return hosts


def _slash24(host: str) -> ipaddress.IPv4Network | None:
    """The /24 a host sits on. Discovery is capped to one /24 by design (§9)."""
    try:
        return ipaddress.ip_network(f"{host}/24", strict=False)
    except (TypeError, ValueError):
        return None


def _seed_hosts(subnets: list[tuple[ipaddress.IPv4Network, int]], config: Config) -> list[tuple[str, int]]:
    """Expand subnets into the host list a sweep will try, with a hard cap."""
    hosts: list[tuple[str, int]] = []
    seen: set[str] = set()
    for subnet, port in subnets:
        if subnet.num_addresses <= 1:
            continue
        base = int(subnet.network_address)
        for offset in range(_HOST_OCTET_MIN + 1, _HOST_OCTET_MAX + 1):
            # The cap counts hosts, not probes: one host contributes one entry per port.
            if len(seen) >= config.discover_max_hosts:
                return hosts
            address = ipaddress.IPv4Address(base + offset)
            host = str(address)
            if host in seen or not _usable(host, config):
                continue
            seen.add(host)
            # design.md §2: the sweep covers every configured device port, not just the first.
            for candidate_port in ((port,) if port else config.device_ports):
                hosts.append((host, candidate_port))
    return hosts


def _sweep(hosts: list[tuple[str, int]], config: Config) -> list[DiscoveredHost]:
    """Run the sweep to completion, or give up. It never hangs longer than one timeout."""
    try:
        return asyncio.run(_sweep_async(hosts, config))
    except (RuntimeError, OSError):
        return []


async def _sweep_async(hosts: list[tuple[str, int]], config: Config) -> list[DiscoveredHost]:
    semaphore = asyncio.Semaphore(max(1, config.discover_concurrency))

    async def probe(host: str, port: int) -> DiscoveredHost | None:
        async with semaphore:
            if not _usable(host, config):
                return None
            if not await _accepts(host, port, config):
                return None
            props = await _read_props(host, port, config)
            return DiscoveredHost(host=host, port=port, source="tcp-sweep", props=props)

    results = await asyncio.gather(*(probe(host, port) for host, port in hosts), return_exceptions=True)
    out: list[DiscoveredHost] = []
    seen: set[str] = set()
    for item in results:
        if isinstance(item, BaseException) or item is None:
            continue
        if item.host in seen:
            continue
        seen.add(item.host)
        out.append(item)
    return out


async def _accepts(host: str, port: int, config: Config) -> bool:
    """A bare TCP connect. No handshake, no credentials, no second guess about who answered."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=config.discover_timeout_seconds,
        )
    except (OSError, TimeoutError, asyncio.TimeoutError):
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def _read_props(host: str, port: int, config: Config) -> tuple[str, ...]:
    """Read `ro.product.*` through the adb wrapper, one key per argv.

    A bare TCP connect proves something is listening; only a device that answers for its own
    properties is a TV. That needs an adb connection first, and it runs off the event loop
    because the adb wrapper is blocking.
    """
    return await asyncio.to_thread(_read_props_blocking, host, port, config)


def _read_props_blocking(host: str, port: int, config: Config) -> tuple[str, ...]:
    target = f"{host}:{port}"
    client = adb.AdbClient.from_config(config)
    connected = client.connect(target)
    if not connected.ok:
        return ()
    try:
        values: list[str] = []
        for key in _PROPS:
            result = client.run(["-s", target, "shell", "getprop", key])
            if not result.ok:
                return ()
            lines = [line.strip() for line in result.lines() if len(line.strip()) <= _MAX_PROP_CHARS]
            if not lines:
                return ()
            values.append(lines[0])
        return tuple(values)
    finally:
        # Verification must not leave a connection behind; the wizard connects deliberately.
        client.disconnect(target)


def _usable(host: str, config: Config) -> bool:
    """The guard every candidate must pass: an IPv4 literal on an allowed network."""
    from .netguard import TargetRejected, normalize_target

    try:
        normalize_target(f"{host}:{min(config.device_ports)}", config.allowed_cidrs, config.device_ports)
    except (TargetRejected, ValueError):
        return False
    return True


_MAX_PROP_CHARS = 128
_MAX_BROADCAST_REPLIES = 8
