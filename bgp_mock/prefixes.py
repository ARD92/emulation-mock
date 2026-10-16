"""Carve a CIDR block into the prefixes carried by L3VPN updates."""

from __future__ import annotations

import ipaddress


def expand_prefix_block(cidr: str, count: int, prefix_length: int | None = None) -> list[str]:
    """Return `count` prefixes inside `cidr`.

    With no prefix_length, one prefix is the block itself. More than one prefix
    uses /24 (IPv4) or /64 (IPv6) when the block can hold them, and a longer
    length when it cannot.
    """
    if count < 1:
        raise ValueError(f"count must be >= 1, got {count}")
    try:
        network = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"prefix must be a CIDR block such as 10.1.0.0/16, got {cidr!r}") from exc
    length = network.prefixlen if prefix_length is None and count == 1 else prefix_length
    if length is None:
        length = _default_length(network, count)
    if length < network.prefixlen or length > network.max_prefixlen:
        raise ValueError(
            f"{network} cannot be split into /{length} prefixes"
        )
    found: list[str] = []
    for subnet in network.subnets(new_prefix=length):
        found.append(str(subnet))
        if len(found) >= count:
            return found
    raise ValueError(
        f"{network} holds {len(found)} /{length} prefixes; count is {count}"
    )


def _default_length(network: ipaddress._BaseNetwork, count: int) -> int:
    preferred = 24 if network.version == 4 else 64
    length = max(network.prefixlen, preferred)
    while length <= network.max_prefixlen:
        if (1 << (length - network.prefixlen)) >= count:
            return length
        length += 1
    raise ValueError(f"{network} cannot hold {count} prefixes")
