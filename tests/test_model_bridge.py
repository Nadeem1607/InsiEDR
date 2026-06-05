from __future__ import annotations

from server.model_bridge import ModelBridge


class DummyBridge(ModelBridge):
    def feature_columns(self) -> list[str]:
        return [
            "file_access_count",
            "after_hours_file_access",
            "daily_unique_filename_count",
            "daily_repeat_file_access_count",
            "daily_repeat_file_ratio",
            "first_file_access_time",
            "logon_risk",
            "file_risk",
            "device_risk",
            "http_risk",
            "overall_risk",
            "daily_risk_delta",
            "daily_risk_rolling_mean_7d",
            "daily_risk_rolling_std_7d",
        ]


class RiskHistoryStorage:
    def list_recent_risk_scores(self, username=None, hostname=None, limit=7):
        return [
            {"risk_score": 40.0},
            {"risk_score": 20.0},
        ]


def test_model_bridge_aliases_and_derives_model_features():
    bridge = DummyBridge()

    features, missing = bridge._ordered_features(
        {
            "file_access_after_hours": 3,
            "daily_file_open_count": 10,
            "daily_file_write_count": 2,
            "daily_file_delete_count": 1,
            "daily_unique_filename_count": 8,
            "first_file_access_time": "09:30:00",
        }
    )

    assert features["after_hours_file_access"] == 3.0
    assert features["file_access_count"] == 13.0
    assert features["daily_repeat_file_access_count"] == 5.0
    assert round(features["daily_repeat_file_ratio"], 6) == round(5 / 13, 6)
    assert features["first_file_access_time"] == 9.5
    assert "after_hours_file_access" not in missing


def test_model_bridge_applies_current_and_rolling_risk_features():
    bridge = DummyBridge()
    features = {}

    bridge._apply_current_risk_features(
        features,
        {
            "overall_score": 0.75,
            "domain_scores": {
                "logon": 0.1,
                "file": 0.2,
                "device": 0.3,
                "http": 0.4,
            },
        },
    )
    bridge._apply_rolling_risk_features(
        RiskHistoryStorage(),
        {"username": "alice", "hostname": "host-1"},
        features,
    )

    assert features["logon_risk"] == 0.1
    assert features["file_risk"] == 0.2
    assert features["device_risk"] == 0.3
    assert features["http_risk"] == 0.4
    assert features["overall_risk"] == 0.75
    assert features["daily_risk_delta"] == 0.35
    assert round(features["daily_risk_rolling_mean_7d"], 6) == 0.3
    assert round(features["daily_risk_rolling_std_7d"], 6) == 0.1
