from __future__ import annotations

from agent.collectors import devices_feature


def test_synthetic_usb_data_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(devices_feature, "IS_WINDOWS", False)
    monkeypatch.delenv("INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA", raising=False)

    features = devices_feature.collect()

    assert features["_collector_status"] == "unsupported"
    assert features["_collector_quality"] == "unsupported"
    assert "synthetic USB collector data is disabled" in features["_collector_message"]
    assert features["usb_connect_count"] == 0


def test_synthetic_usb_data_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(devices_feature, "IS_WINDOWS", False)
    monkeypatch.setenv("INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA", "1")

    features = devices_feature.collect()

    assert features["synthetic_data"] is True
    assert features["usb_connect_count"] == 2
    assert features["_collector_quality"] == "local_only"
