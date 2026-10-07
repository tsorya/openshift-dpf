"""Read a local TCP source tuple from Linux /proc/net/tcp."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

_TCP_CONNECTED_STATES = {"01", "02"}  # ESTABLISHED, SYN_SENT


def ipv4_hex_to_dotted(value: str) -> str:
    packed = bytes.fromhex(value)
    if len(packed) != 4:
        raise ValueError(f"invalid IPv4 hex address: {value}")
    return socket.inet_ntoa(packed[::-1])


def parse_proc_net_tcp(
    table: str, dest_ip: str, dest_port: int
) -> tuple[str | None, int | None]:
    dest = ipaddress.ip_address(dest_ip)
    if dest.version != 4:
        return None, None
    remote = f"{socket.inet_aton(str(dest))[::-1].hex().upper()}:{int(dest_port):04X}"
    for line in table.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, rem, state = parts[1], parts[2], parts[3]
        if rem.upper() != remote or state not in _TCP_CONNECTED_STATES:
            continue
        local_ip_hex, local_port_hex = local.split(":")
        source_port = int(local_port_hex, 16)
        if not source_port:
            continue
        return ipv4_hex_to_dotted(local_ip_hex), source_port
    return None, None


def tcp_source_to_dest(
    dest_ip: str, dest_port: int, pid: int | None = None
) -> tuple[str | None, int | None]:
    path = Path(f"/proc/{pid}/net/tcp" if pid else "/proc/self/net/tcp")
    try:
        table = path.read_text()
    except OSError:
        return None, None
    return parse_proc_net_tcp(table, dest_ip, dest_port)
