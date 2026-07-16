from __future__ import annotations

from typing import Any, Dict

from server.detectors.base import Detector


class LstmForecaster(Detector):
    """
    LSTM Time-Series Forecaster (Phase 3).
    Currently explicitly disabled pending sufficient sequential feature history 
    and thorough drift monitoring evaluation.
    """

    @property
    def name(self) -> str:
        return "lstm_forecaster"

    def detect(self, payload_id: str, agent_id: str, username: str, features: Dict[str, float], baseline: Any) -> Dict[str, Any]:
        return {
            "detector_name": self.name,
            "score": 0.0,
            "confidence": 0.0,
            "is_anomaly": False,
            "feature_contributions": {},
            "reason": "LSTM Disabled pending drift analysis."
        }
