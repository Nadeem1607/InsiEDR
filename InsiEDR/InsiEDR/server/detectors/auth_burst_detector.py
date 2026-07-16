from __future__ import annotations

from typing import Any, Dict

from server.config import config
from server.detectors.base import Detector


class AuthBurstDetector(Detector):
    @property
    def name(self) -> str:
        return "auth_burst"

    def detect(self, payload_id: str, agent_id: str, username: str, features: Dict[str, float], baseline: Any) -> Dict[str, Any]:
        result = {
            "detector_name": self.name,
            "score": 0.0,
            "confidence": 0.0,
            "is_anomaly": False,
            "feature_contributions": {},
            "reason": "Normal authentication activity."
        }

        # If no baseline is available, we cannot confidently detect a burst.
        if not baseline:
            result["reason"] = "No baseline available."
            return result
        
        # Cold start confidence derived from baseline sample count
        confidence = min(baseline.sample_count / 14.0, 1.0) if baseline.sample_count > 0 else 0.1
        result["confidence"] = confidence

        # Extract actual short-term EDR features instead of generic logon_count
        events_per_minute = features.get("edr_auth_events_per_minute_window", 0.0)
        failed_ratio = features.get("edr_failed_auth_ratio_window", 0.0)
        
        baseline_rate_mean = baseline.feature_means.get("edr_auth_events_per_minute_window", 0.0)
        baseline_rate_std = max(baseline.feature_stds.get("edr_auth_events_per_minute_window", 1.0), 0.1)
        
        baseline_ratio_mean = baseline.feature_means.get("edr_failed_auth_ratio_window", 0.0)
        baseline_ratio_std = max(baseline.feature_stds.get("edr_failed_auth_ratio_window", 1.0), 0.1)

        # Calculate Z-Scores for bursts using the specific EDR telemetry
        rate_z = (events_per_minute - baseline_rate_mean) / baseline_rate_std
        ratio_z = (failed_ratio - baseline_ratio_mean) / baseline_ratio_std

        calibrated_threshold = config.zscore_calibration_threshold

        # Identify statistical spikes
        if rate_z > calibrated_threshold or ratio_z > calibrated_threshold:
            result["is_anomaly"] = True
            
            # The final score is the edr_auth_burst_score representation
            edr_auth_burst_score = max(rate_z, ratio_z) * 10.0
            result["score"] = edr_auth_burst_score
            
            result["feature_contributions"] = {
                "edr_auth_events_per_minute_window": rate_z, 
                "edr_failed_auth_ratio_window": ratio_z
            }
            
            if ratio_z > calibrated_threshold and rate_z > calibrated_threshold:
                result["reason"] = f"Abnormal burst of authentication activity combined with a high failure ratio (Burst Z-Score: {edr_auth_burst_score:.2f})."
            elif ratio_z > calibrated_threshold:
                result["reason"] = f"Abnormally high ratio of failed authentications detected (Burst Z-Score: {edr_auth_burst_score:.2f})."
            else:
                result["reason"] = f"Abnormal burst of authentication activity detected (Burst Z-Score: {edr_auth_burst_score:.2f})."
                
        return result
