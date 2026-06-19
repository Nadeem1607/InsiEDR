import pytest
from server.baseline.engine import BaselineEngine, UserBaseline
from server.detectors.auth_burst_detector import AuthBurstDetector
from server.detectors.zscore_detector import ZScoreDetector
from server.risk.aggregator import RiskAggregator

class MockStorage:
    def __init__(self):
        self.baselines = {}
    def load_baseline(self, user):
        return self.baselines.get(user)
    def save_baseline(self, payload):
        self.baselines[payload["username"]] = payload

def test_baseline_cold_start():
    """Assert new users scale confidence linearly until sufficient history."""
    engine = BaselineEngine(storage=MockStorage(), window_days=30)
    baseline = engine.get_baseline("new_user") or UserBaseline(username="new_user")
    
    # Should create a fresh baseline
    assert baseline is not None
    assert baseline.sample_count == 0
    
    # Confidence must start extremely low to prevent false positives
    assert baseline.confidence_score <= 0.1
    
    # Update baseline and verify confidence climbs
    engine.update_baseline("new_user", {"file_copy_count": 5}, hour=12)
    baseline = engine.get_baseline("new_user")
    # Linear scale based on 14 samples
    assert baseline.confidence_score > 0.0

def test_auth_burst_detector():
    """Assert server-side burst calculation triggers correctly."""
    detector = AuthBurstDetector()
    
    baseline = UserBaseline(username="test")
    baseline.feature_means = {"logon_count": 1.0, "failed_logon_count": 0.0}
    baseline.feature_stds = {"logon_count": 0.5, "failed_logon_count": 0.1}
    
    features = {
        "logon_count": 5,           # Major deviation
        "failed_logon_count": 12    # Massive burst
    }
    
    result = detector.detect("payload-1", "agent-1", "test", features, baseline)
    assert result["is_anomaly"] is True
    assert result["score"] > 80.0
    assert "failed_logon_count" in result["feature_contributions"]

def test_zscore_calibration():
    """Assert ZScore uses calibrated variance, rejecting hard-coded cutoffs."""
    # Instantiated with a highly sensitive multiplier
    detector = ZScoreDetector(sensitivity_multiplier=0.5) 
    
    baseline = UserBaseline(username="test")
    baseline.feature_means = {"bytes_sent": 1000}
    baseline.feature_stds = {"bytes_sent": 100}
    
    # At value 1200, Z-score = 2.0. 
    # With multiplier 0.5, threshold = 1.5. This SHOULD trigger.
    features = {"bytes_sent": 1200}
    result = detector.detect("p-1", "a-1", "test", features, baseline)
    
    assert result["is_anomaly"] is True
    assert result["feature_contributions"]["bytes_sent"] == 2.0

def test_risk_aggregation_logic():
    """Assert noisy detectors are properly weighted and capped."""
    aggregator = RiskAggregator(storage=MockStorage())
    
    baseline = UserBaseline(username="test")
    baseline.sample_count = 14 # 1.0 Confidence
    
    detector_results = [
        {
            "detector_name": "zscore",
            "is_anomaly": True,
            "score": 40.0,
            "confidence": 0.8,
            "feature_contributions": {"file_writes": 3.1},
            "reason": "Minor file deviation"
        },
        {
            "detector_name": "isolation_forest",
            "is_anomaly": True,
            "score": 75.0,
            "confidence": 0.9,
            "feature_contributions": {},
            "reason": "Isolation Forest Outlier"
        }
    ]
    
    final_risk = aggregator.aggregate_detectors(detector_results)
    # Aggregator must apply Agreement Amplifier because > 1 detector flagged an anomaly
    assert final_risk["risk_score"] > 60.0 # High risk category
    assert final_risk["risk_level"] in ["high", "critical"]
    assert "Minor file deviation" in final_risk["summary"]
