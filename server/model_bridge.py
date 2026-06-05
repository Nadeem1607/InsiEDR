from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from server.config import config


REQUIRED_MODEL_ARTIFACTS = (
    "domain_isolation_forest.pkl",
    "feature_scaler.pkl",
    "ridge_models.pkl",
    "rvfl_metadata.json",
    "feature_columns.json",
)

REQUIRED_MODEL_DEPENDENCIES = (
    "joblib",
    "numpy",
    "sklearn",
    "torch",
)

FEATURE_ALIASES = {
    "after_hours_file_access": ("file_access_after_hours",),
    "weekend_file_access": ("file_access_weekend",),
    "first_file_access_time": ("first_file_activity_time", "first_file_open_time"),
    "last_file_access_time": ("last_file_activity_time", "last_file_open_time"),
    "first_usb_usage_time": ("first_usb_time",),
    "last_usb_usage_time": ("last_usb_time",),
    "daily_unique_filename_count": ("unique_filename_count",),
    "daily_new_filename_count": ("new_filename_count",),
    "daily_http_request_count": ("http_request_count", "http_count"),
    "daily_unique_domain_count": ("unique_domain_count",),
    "daily_new_domain_count": ("new_domain_count",),
    "daily_external_domain_ratio": ("external_domain_ratio",),
    "daily_device_connect_count": ("usb_connect_count",),
    "daily_unique_pc_count": ("unique_pc_count",),
}

DOMAIN_RISK_FEATURES = {
    "logon": "logon_risk",
    "file": "file_risk",
    "device": "device_risk",
    "http": "http_risk",
}


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class ModelBridge:
    """Backend handoff layer for the stateless model-inference package.

    The bridge is intentionally tolerant: ingestion must not fail just because
    trained artifacts are absent or the model package is not importable.
    """

    def __init__(self, inference_dir: str | Path | None = None) -> None:
        self.inference_dir = Path(inference_dir or config.model_inference_dir).resolve()
        self.models_dir = self.inference_dir / "models"
        self._feature_columns: list[str] | None = None
        self._inference_module = None

    def readiness(self) -> dict[str, Any]:
        missing = [name for name in REQUIRED_MODEL_ARTIFACTS if not (self.models_dir / name).exists()]
        missing_dependencies = [
            name for name in REQUIRED_MODEL_DEPENDENCIES if importlib.util.find_spec(name) is None
        ]
        return {
            "enabled": config.enable_model_pipeline,
            "inference_dir": str(self.inference_dir),
            "models_dir": str(self.models_dir),
            "ready": config.enable_model_pipeline and not missing and not missing_dependencies,
            "missing_artifacts": missing,
            "missing_dependencies": missing_dependencies,
        }

    def feature_columns(self) -> list[str]:
        if self._feature_columns is None:
            path = self.models_dir / "feature_columns.json"
            if path.exists():
                self._feature_columns = json.loads(path.read_text(encoding="utf-8"))
            else:
                self._feature_columns = []
        return self._feature_columns

    def _load_inference_module(self):
        if self._inference_module is not None:
            return self._inference_module
        src_dir = self.inference_dir / "src"
        if str(self.inference_dir) not in sys.path:
            sys.path.insert(0, str(self.inference_dir))
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))
        self._inference_module = importlib.import_module("src.server.inference")
        return self._inference_module

    @staticmethod
    def _payload_features(payload: dict[str, Any]) -> dict[str, Any]:
        features: dict[str, Any] = {}
        for collector in payload.get("collectors", []):
            if not isinstance(collector, dict) or collector.get("status") != "success":
                continue
            collector_payload = collector.get("payload")
            if not isinstance(collector_payload, dict):
                continue
            for key, value in collector_payload.items():
                if isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        if isinstance(nested_value, dict):
                            for feature_name, feature_value in nested_value.items():
                                features.setdefault(feature_name, feature_value)
                        else:
                            features.setdefault(key, value)
                else:
                    features.setdefault(key, value)
        return features

    def _features_for_payload(self, storage, payload: dict[str, Any]) -> dict[str, Any]:
        getter = getattr(storage, "get_feature_vector", None)
        if callable(getter):
            stored = getter(payload["payload_id"])
            if stored:
                return stored
        return self._payload_features(payload)

    @staticmethod
    def _numeric(value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(value)
        except (TypeError, ValueError):
            return ModelBridge._time_to_numeric(value)

    @staticmethod
    def _time_to_numeric(value: Any) -> float:
        text = str(value or "").strip()
        if not text:
            return 0.0
        if "T" in text:
            text = text.split("T", 1)[1]
        if " " in text:
            text = text.rsplit(" ", 1)[-1]
        text = text.replace("Z", "").split("+", 1)[0]
        parts = text.split(":")
        try:
            if len(parts) >= 2:
                hour = int(parts[0])
                minute = int(parts[1])
                return float(hour) + (float(minute) / 60.0)
        except ValueError:
            return 0.0
        return 0.0

    @staticmethod
    def _with_aliases(raw_features: dict[str, Any]) -> dict[str, Any]:
        mapped = dict(raw_features)
        for canonical, aliases in FEATURE_ALIASES.items():
            if canonical in mapped and mapped[canonical] is not None:
                continue
            for alias in aliases:
                if alias in mapped and mapped[alias] is not None:
                    mapped[canonical] = mapped[alias]
                    break
        if "file_access_count" not in mapped:
            open_count = mapped.get("daily_file_open_count", mapped.get("file_open_count", 0))
            write_count = mapped.get("daily_file_write_count", mapped.get("file_write_count", 0))
            delete_count = mapped.get("daily_file_delete_count", mapped.get("file_delete_count", 0))
            mapped["file_access_count"] = ModelBridge._numeric(open_count) + ModelBridge._numeric(write_count) + ModelBridge._numeric(delete_count)
        if "daily_repeat_file_access_count" not in mapped:
            access = ModelBridge._numeric(mapped.get("file_access_count"))
            unique = ModelBridge._numeric(mapped.get("daily_unique_filename_count"))
            mapped["daily_repeat_file_access_count"] = max(access - unique, 0.0)
        if "daily_repeat_file_ratio" not in mapped:
            access = max(ModelBridge._numeric(mapped.get("file_access_count")), 1.0)
            mapped["daily_repeat_file_ratio"] = ModelBridge._numeric(mapped.get("daily_repeat_file_access_count")) / access
        return mapped

    def _ordered_features(self, raw_features: dict[str, Any]) -> tuple[dict[str, float], list[str]]:
        columns = self.feature_columns()
        mapped = self._with_aliases(raw_features)
        missing = [name for name in columns if name not in mapped or mapped.get(name) is None]
        ordered = {name: self._numeric(mapped.get(name)) for name in columns}
        return ordered, missing

    def _daily_sequence(self, storage, payload: dict[str, Any], current_features: dict[str, float]) -> list[dict[str, Any]]:
        loader = getattr(storage, "list_daily_feature_vectors", None)
        if callable(loader):
            rows = loader(
                username=payload.get("username"),
                hostname=payload.get("hostname"),
                limit=16,
            )
            if rows:
                return rows
        return [{"date": str(payload.get("collected_at", ""))[:10], "features": current_features}]

    def process_payload(self, storage, payload: dict[str, Any]) -> dict[str, Any]:
        if not config.enable_model_pipeline:
            result = self._skipped(payload, "disabled", "Model pipeline disabled by configuration.")
            self._persist_model_output(storage, result)
            return result

        readiness = self.readiness()
        raw_features = self._features_for_payload(storage, payload)
        ordered_features, missing = self._ordered_features(raw_features)

        if not readiness["ready"]:
            result = self._skipped(
                payload,
                "missing_artifacts",
                "Model artifacts are not available: " + ", ".join(readiness["missing_artifacts"]),
                missing_features=missing,
            )
            self._persist_model_output(storage, result)
            return result
        if readiness["missing_dependencies"]:
            result = self._skipped(
                payload,
                "missing_dependencies",
                "Model dependencies are not available: " + ", ".join(readiness["missing_dependencies"]),
                missing_features=missing,
            )
            self._persist_model_output(storage, result)
            return result

        try:
            inference = self._load_inference_module()
            current_result = inference.predict_current_risk({"features": ordered_features})
            self._apply_current_risk_features(ordered_features, current_result)
            self._apply_rolling_risk_features(storage, payload, ordered_features)
            self._persist_current_result(storage, payload, current_result, missing)

            sequence = self._adapt_sequence(self._daily_sequence(storage, payload, ordered_features))
            if len(sequence) >= 16:
                behavioral_result = inference.predict_behavioral_risk(
                    {
                        "payload_id": payload["payload_id"],
                        "username": payload.get("username"),
                        "hostname": payload.get("hostname"),
                        "daily_sequence": sequence,
                    }
                )
                self._persist_behavioral_result(storage, payload, behavioral_result)
            return {"status": "processed", "current": current_result, "missing_features": missing}
        except Exception as exc:
            result = self._skipped(payload, "inference_error", f"Model inference failed: {type(exc).__name__}", missing)
            self._persist_model_output(storage, result)
            return result

    def _apply_current_risk_features(self, features: dict[str, float], current_result: dict[str, Any]) -> None:
        domain_scores = current_result.get("domain_scores") or {}
        for domain, feature_name in DOMAIN_RISK_FEATURES.items():
            if domain in domain_scores:
                features[feature_name] = self._numeric(domain_scores[domain])
        if current_result.get("overall_score") is not None:
            features["overall_risk"] = self._numeric(current_result.get("overall_score"))

    def _apply_rolling_risk_features(self, storage, payload: dict[str, Any], features: dict[str, float]) -> None:
        history_loader = getattr(storage, "list_recent_risk_scores", None)
        if not callable(history_loader):
            return
        try:
            history = history_loader(username=payload.get("username"), hostname=payload.get("hostname"), limit=7)
        except Exception:
            return
        scores = [self._numeric(row.get("risk_score")) / 100.0 for row in history if row.get("risk_score") is not None]
        current = self._numeric(features.get("overall_risk"))
        if scores:
            features["daily_risk_delta"] = current - scores[0]
            features["daily_risk_rolling_mean_7d"] = float(sum(scores) / len(scores))
            if len(scores) > 1:
                mean = features["daily_risk_rolling_mean_7d"]
                features["daily_risk_rolling_std_7d"] = float((sum((score - mean) ** 2 for score in scores) / len(scores)) ** 0.5)
            else:
                features["daily_risk_rolling_std_7d"] = 0.0

    def _adapt_sequence(self, sequence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        adapted = []
        for day in sequence:
            features, _ = self._ordered_features(day.get("features") or {})
            adapted.append({"date": day.get("date"), "features": features})
        return adapted

    @staticmethod
    def _skipped(
        payload: dict[str, Any],
        reason: str,
        summary: str,
        missing_features: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "payload_id": payload.get("payload_id"),
            "agent_id": payload.get("agent_id"),
            "username": payload.get("username"),
            "detector_name": "model_bridge",
            "model_version": "v1",
            "score": None,
            "confidence": 0.0,
            "is_anomaly": False,
            "feature_contributions_json": {"status": "skipped", "reason": reason, "missing_features": missing_features or []},
            "reason_summary": summary,
        }

    @staticmethod
    def _persist_model_output(storage, output: dict[str, Any]) -> None:
        saver = getattr(storage, "save_model_output", None)
        if callable(saver):
            try:
                saver(output)
            except Exception:
                pass

    def _persist_current_result(
        self,
        storage,
        payload: dict[str, Any],
        result: dict[str, Any],
        missing_features: list[str],
    ) -> None:
        output = {
            "payload_id": payload.get("payload_id"),
            "agent_id": payload.get("agent_id"),
            "username": payload.get("username"),
            "detector_name": result.get("detector", "isolation_forest"),
            "model_version": "v1",
            "score": result.get("overall_score"),
            "confidence": 1.0 if not missing_features else 0.6,
            "is_anomaly": result.get("risk_level") in {"HIGH", "MEDIUM"},
            "feature_contributions_json": {
                "domain_scores": result.get("domain_scores", {}),
                "missing_features": missing_features,
            },
            "reason_summary": f"Current risk level: {result.get('risk_level', 'UNKNOWN')}",
        }
        self._persist_model_output(storage, output)
        risk_saver = getattr(storage, "save_risk_event", None)
        if callable(risk_saver):
            try:
                risk_saver(
                    {
                        "payload_id": payload.get("payload_id"),
                        "agent_id": payload.get("agent_id"),
                        "username": payload.get("username"),
                        "risk_score": self._numeric(result.get("overall_score")) * 100.0,
                        "risk_level": str(result.get("risk_level", "unknown")).lower(),
                        "correlated_signals_json": result.get("domain_scores", {}),
                        "summary": output["reason_summary"],
                    }
                )
            except Exception:
                pass

    def _persist_behavioral_result(self, storage, payload: dict[str, Any], result: dict[str, Any]) -> None:
        output = {
            "payload_id": payload.get("payload_id"),
            "agent_id": payload.get("agent_id"),
            "username": payload.get("username"),
            "detector_name": "redrvfl_behavioral",
            "model_version": result.get("model_versions", {}).get("rvfl_model", "v1"),
            "score": result.get("rvfl_error"),
            "confidence": 1.0,
            "is_anomaly": result.get("behavioral_risk") in {"HIGH", "MEDIUM"},
            "feature_contributions_json": result,
            "reason_summary": result.get("recommended_action"),
        }
        self._persist_model_output(storage, output)


bridge = ModelBridge()
