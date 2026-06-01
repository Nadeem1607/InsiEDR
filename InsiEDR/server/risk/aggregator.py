from __future__ import annotations

from typing import Any, Dict


class RiskAggregator:
	"""Lightweight risk aggregator used by API surfaces to summarise risk metrics.

	This implementation queries the provided storage for basic counts and returns
	a small summary object. It's intentionally conservative and only depends on
	the existing storage interface.
	"""

	def __init__(self, storage) -> None:
		self.storage = storage

	def summary(self) -> Dict[str, Any]:
		stats = self.storage.get_stats() if hasattr(self.storage, "get_stats") else {}
		return {
			"ok": True,
			"agents": stats.get("agents", 0),
			"logs": stats.get("logs", 0),
			"collector_results": stats.get("collector_results", 0),
			"anomalies": stats.get("anomalies", 0),
			"baselines": stats.get("baselines", 0),
		}

