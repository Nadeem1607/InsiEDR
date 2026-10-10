"""Adapter for the leakage-corrected model bundle and signed SHAP evidence."""
from __future__ import annotations

import datetime
import logging
import sys
from pathlib import Path
from typing import Any

from server.config import config
from server.detectors.base import Detector

logger = logging.getLogger("advanced_pipeline_detector")


def _ensure_g_model_on_path():
    root = str(Path(config.model_inference_dir).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)


class AdvancedPipelineDetector(Detector):
    @property
    def name(self):
        return "advanced_pipeline"

    def __init__(self):
        super().__init__()
        self._engine = None
        self._load_error = None
        try:
            _ensure_g_model_on_path()
            from src.server.inference import get_engine
            self._engine = get_engine(config.g_model_models_dir)
        except Exception as error:
            self._load_error = str(error)
            logger.error("Model load failed: %s", error)

    def _build_daily_sequence(self, username, features, storage, hostname=None, collected_at=None):
        from server.model_bridge import ModelBridge

        timestamp = (datetime.datetime.fromisoformat(str(collected_at).replace("Z", "+00:00"))
                     if collected_at else datetime.datetime.now(datetime.timezone.utc))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=datetime.timezone.utc)
        today = timestamp.astimezone(datetime.timezone.utc).date().isoformat()
        by_date = {}
        loader = getattr(storage, "list_daily_feature_vectors", None)
        if callable(loader):
            rows = loader(username=username, hostname=hostname,
                          limit=config.model_history_observations)
            for row in rows:
                day = str(row.get("date", ""))[:10]
                if not day or day > today:
                    continue
                mapped = ModelBridge._with_aliases(row.get("features") or {})
                by_date[day] = {"date": day, "features": {
                    name: ModelBridge._numeric(mapped.get(name)) for name in self._engine.feature_columns}}
        # Replace a stored snapshot of this date instead of counting today twice.
        by_date[today] = {"date": today, "features": dict(features)}
        return [by_date[day] for day in sorted(by_date)][-config.model_history_observations:]

    def detect(self, payload_id, agent_id, username, features, baseline, storage=None,
               hostname=None, collected_at=None) -> dict[str, Any]:
        confidence = min(baseline.sample_count / 14.0, 1.0) if baseline and baseline.sample_count else .3
        result = {"detector_name": self.name, "score": 0.0, "confidence": 0.0,
                  "is_anomaly": False, "feature_contributions": {},
                  "reason": f"Model unavailable: {self._load_error}"}
        if self._engine is None:
            return result
        try:
            sequence = self._build_daily_sequence(
                username, features, storage, hostname=hostname, collected_at=collected_at)
            model = self._engine.predict_user_risk({
                "payload_id": payload_id, "username": username,
                "hostname": hostname or agent_id, "daily_sequence": sequence})
            detectors = model["detectors"]
            scenario = detectors["xgboost"]
            current = detectors["isolation_forest"]
            behavioral = detectors["red_rvfl"]
            full = model["score_v2"] is not None
            result.update({
                "score": model["risk_score"], "confidence": confidence if full else confidence * .5,
                "is_anomaly": model["risk_level"] in ("HIGH", "MEDIUM"),
                "feature_contributions": {
                    "domain_scores": current["domain_scores"], "overall_risk": current["overall_score"],
                    "raw_overall_risk": current["raw_overall_risk"],
                    "predicted_scenario": scenario["scenario"], "scenario_confidence": scenario["confidence"],
                    "scenario_probs": {key: value for key, value in scenario.items() if key.endswith("_prob")},
                    "rvfl_error": behavioral["rvfl_error"], "score_v2": model["score_v2"],
                    "score_components": model["score_components"], "history": model["history"],
                    "explanations": model["explanations"], "mode": model["mode"],
                    "display_score_contract": model["display_score_contract"],
                    "model_version": model["model_versions"]["pipeline"],
                    "days_in_sequence": len(sequence),
                    "days_needed_for_rvfl": model["sequence_length_expected"] + 1,
                },
                "reason": (
                    f"SHAP pipeline: scenario={scenario['scenario']}; "
                    + (f"score_v2={model['score_v2']:.8g}, "
                       f"{model['score_components']['sequence_count']} sequence errors"
                       if full else f"warmup {len(sequence)}/{model['sequence_length_expected'] + 1} observations")
                ),
            })
        except Exception as error:
            logger.exception("Inference failed for %s", username)
            result["reason"] = f"Model inference error: {error}"
        return result
