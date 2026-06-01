from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

import psutil


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_net_connections() -> list[Any]:
    try:
        return list(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, PermissionError, OSError):
        return []


def _connection_counts(connections: list[Any]) -> dict[str, int]:
    established = listening = loopback = 0
    remote_addresses: set[str] = set()
    for conn in connections:
        status = str(getattr(conn, "status", "") or "").upper()
        local = getattr(conn, "laddr", None)
        remote = getattr(conn, "raddr", None)
        if status == "ESTABLISHED":
            established += 1
        if status == "LISTEN":
            listening += 1
        if local and getattr(local, "ip", "") in {"127.0.0.1", "::1"}:
            loopback += 1
        if remote and getattr(remote, "ip", ""):
            remote_addresses.add(str(remote.ip))
    return {
        "network_active_connection_count": len(connections),
        "network_established_connection_count": established,
        "network_listening_connection_count": listening,
        "network_loopback_connection_count": loopback,
        "network_unique_remote_address_count": len(remote_addresses),
    }


def _interface_summaries() -> list[dict[str, Any]]:
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    summaries: list[dict[str, Any]] = []
    for name, stat in sorted(stats.items()):
        io = counters.get(name)
        summaries.append(
            {
                "name": name,
                "is_up": bool(stat.isup),
                "speed_mbps": int(stat.speed or 0),
                "mtu": int(stat.mtu or 0),
                "bytes_sent": int(getattr(io, "bytes_sent", 0) if io else 0),
                "bytes_recv": int(getattr(io, "bytes_recv", 0) if io else 0),
                "packets_sent": int(getattr(io, "packets_sent", 0) if io else 0),
                "packets_recv": int(getattr(io, "packets_recv", 0) if io else 0),
            }
        )
    return summaries


def collect_features() -> dict[str, Any]:
    """Collect passive local network counters without packet capture or classification."""
    total = psutil.net_io_counters()
    interfaces = _interface_summaries()
    connections = _safe_net_connections()
    features: dict[str, Any] = {
        "collected_at": _utc_now_iso(),
        "hostname": socket.gethostname(),
        "network_interface_count": len(interfaces),
        "network_interfaces_up_count": sum(1 for item in interfaces if item["is_up"]),
        "network_bytes_sent": int(total.bytes_sent),
        "network_bytes_recv": int(total.bytes_recv),
        "network_packets_sent": int(total.packets_sent),
        "network_packets_recv": int(total.packets_recv),
        "network_errors_in": int(total.errin),
        "network_errors_out": int(total.errout),
        "network_dropin": int(total.dropin),
        "network_dropout": int(total.dropout),
        "network_interfaces": interfaces,
    }
    features.update(_connection_counts(connections))
    return features


def collect() -> dict[str, Any]:
    return collect_features()
