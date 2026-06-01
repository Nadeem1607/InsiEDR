from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Any, Dict, Optional

from server.storage.base import BaseStorage


@dataclass
class UserBaseline:
	username: str
	feature_means: Dict[str, float] = field(default_factory=dict)
	feature_stds: Dict[str, float] = field(default_factory=dict)
	sample_count: int = 0
	hour_profiles: Dict[int, Dict[str, float]] = field(default_factory=dict)
	last_updated: str = ""
	decay_factor: float = 0.05


class BaselineEngine:
	def __init__(self, storage: BaseStorage, decay: float = 0.05) -> None:
		self.storage = storage
		self.decay = decay

	def get_baseline(self, user: str) -> Optional[UserBaseline]:
		row = self.storage.load_baseline(user)
		if not row:
			return None
		metadata = row.get("metadata_json") or {}
		return UserBaseline(
			username=row.get("username") or user,
			feature_means=dict(metadata.get("feature_means") or {}),
			feature_stds=dict(metadata.get("feature_stds") or {}),
			sample_count=int(row.get("sample_count") or 0),
			hour_profiles=dict(metadata.get("hour_profiles") or {}),
			last_updated=row.get("created_at") or "",
			decay_factor=float(metadata.get("decay_factor") or self.decay),
		)

	def update_baseline(self, user: str, features: Dict[str, float], hour: int):
		current = self.get_baseline(user) or UserBaseline(username=user, decay_factor=self.decay)
		new_means = dict(current.feature_means)
		new_stds = dict(current.feature_stds)
		new_counts = current.sample_count + 1
		for feature_name, value in features.items():
			previous = new_means.get(feature_name, value)
			updated = (1 - self.decay) * previous + self.decay * value
			new_means[feature_name] = updated
			new_stds[feature_name] = abs(value - updated)
		payload = {
			"agent_id": None,
			"username": user,
			"feature_name": "__aggregate__",
			"baseline_scope": "user",
			"window_start": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
			"window_end": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
			"mean_value": 0.0,
			"std_value": 0.0,
			"sample_count": new_counts,
			"metadata_json": {
				"feature_means": new_means,
				"feature_stds": new_stds,
				"hour_profiles": current.hour_profiles,
				"decay_factor": self.decay,
			},
			"created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
		}
		self.storage.save_baseline(payload)
		return payload

	def get_deviation_vector(self, user: str, features: Dict[str, float]) -> Dict[str, float]:
		baseline = self.get_baseline(user)
		if baseline is None:
			return {name: 0.0 for name in features}
		deviations: Dict[str, float] = {}
		for name, value in features.items():
			mean_value = baseline.feature_means.get(name, 0.0)
			std_value = baseline.feature_stds.get(name, 1.0) or 1.0
			deviations[name] = (value - mean_value) / std_value
		return deviations

	def get_rolling_window(self, user: str, days: int = 7) -> Dict[str, Any]:
		baseline = self.get_baseline(user)
		if baseline is None:
			return {"user": user, "days": days, "samples": []}
		return {
			"user": user,
			"days": days,
			"samples": [
				{
					"feature": feature,
					"mean": baseline.feature_means.get(feature, 0.0),
					"std": baseline.feature_stds.get(feature, 0.0),
				}
				for feature in sorted(baseline.feature_means)
			],
		}
