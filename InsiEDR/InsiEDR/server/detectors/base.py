from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class Detector(ABC):
    """Abstract base class for Phase 2 Detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique name of the detector."""
        pass

    @abstractmethod
    def detect(self, payload_id: str, agent_id: str, username: str, features: Dict[str, float], baseline: Any) -> Dict[str, Any]:
        """
        Evaluate the normalized features against the baseline.

        Returns:
            dict: {
                "detector_name": str,
                "score": float,            # Severity score (e.g. 0.0 to 100.0 or unbounded Z-score)
                "confidence": float,       # 0.0 to 1.0
                "is_anomaly": bool,
                "feature_contributions": dict[str, float],
                "reason": str,
            }
        """
        pass
