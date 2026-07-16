from __future__ import annotations

import json

from agent.collectors import discover_collectors
from agent.collectors import network_monitor


def test_network_monitor_collects_passive_json_serializable_features(monkeypatch):
    class Counters:
        bytes_sent = 10
        bytes_recv = 20
        packets_sent = 3
        packets_recv = 4
        errin = 0
        errout = 1
        dropin = 0
        dropout = 0

    class IfStat:
        isup = True
        speed = 1000
        mtu = 1500

    class Address:
        def __init__(self, ip):
            self.ip = ip

    class Conn:
        status = "ESTABLISHED"
        laddr = Address("127.0.0.1")
        raddr = Address("10.0.0.5")

    class IfAddr:
        family = network_monitor.socket.AF_INET
        address = "192.0.2.10"
        netmask = "255.255.255.0"
        broadcast = "192.0.2.255"
        ptp = None

    monkeypatch.setattr(network_monitor.psutil, "net_io_counters", lambda pernic=False: {"eth0": Counters()} if pernic else Counters())
    monkeypatch.setattr(network_monitor.psutil, "net_if_stats", lambda: {"eth0": IfStat()})
    monkeypatch.setattr(network_monitor.psutil, "net_if_addrs", lambda: {"eth0": [IfAddr()]})
    monkeypatch.setattr(network_monitor.psutil, "net_connections", lambda kind: [Conn()])

    features = network_monitor.collect_features()

    assert features["network_interface_count"] == 1
    assert features["network_interfaces_up_count"] == 1
    assert features["network_active_connection_count"] == 1
    assert features["network_unique_remote_address_count"] == 1
    assert features["network_interfaces"][0]["errors_out"] == 1
    assert features["network_interfaces"][0]["addresses"][0]["family"] == "ipv4"
    assert "suspicious" not in json.dumps(features).lower()
    assert "alert" not in json.dumps(features).lower()
    json.dumps(features)


def test_network_monitor_handles_connection_permission_denied(monkeypatch):
    class Counters:
        bytes_sent = bytes_recv = packets_sent = packets_recv = 0
        errin = errout = dropin = dropout = 0

    monkeypatch.setattr(network_monitor.psutil, "net_io_counters", lambda pernic=False: {} if pernic else Counters())
    monkeypatch.setattr(network_monitor.psutil, "net_if_stats", lambda: {})

    def denied(kind):
        raise PermissionError("no access")

    monkeypatch.setattr(network_monitor.psutil, "net_connections", denied)

    features = network_monitor.collect_features()

    assert features["network_active_connection_count"] == 0
    assert features["network_interface_count"] == 0


def test_network_monitor_can_be_discovered_when_enabled():
    collectors = discover_collectors(enabled=("network-monitor",), hostname="qa-host")

    assert len(collectors) == 1
    assert collectors[0].name == "network-monitor"
