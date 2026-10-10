"""Inference for the exported leakage-corrected IF/XGBoost/RedRVFL bundle."""
import hashlib
import json
from importlib.metadata import version
from pathlib import Path
from functools import lru_cache
import threading

import joblib
import numpy as np
import pandas as pd
import shap
import torch
import xgboost as xgb

from src.score_explanations import normalize_shap_values, check_shap_additivity
from src.server.features.feature_schema import IF_GROUPS


class InferenceEngine:
    def __init__(self, models_dir=None):
        root = Path(__file__).resolve().parents[3]
        self.models_dir = Path(models_dir or root / "artifacts/shap_v1")
        self._lock = threading.RLock()
        self._load_models()

    def _load_models(self):
        config_path = self.models_dir / "pipeline_config.json"
        self.config = json.loads(config_path.read_text(encoding="utf-8"))
        if self.config.get("schema_version") != 1:
            raise ValueError("Unsupported pipeline bundle schema.")
        for package, expected in self.config["versions"].items():
            actual = version(package)
            if actual != expected:
                raise ValueError(f"Bundle requires {package}=={expected}; found {actual}.")
        for name, expected in self.config["sha256"].items():
            if Path(name).name != name:
                raise ValueError("Invalid artifact path in bundle manifest.")
            if hashlib.sha256((self.models_dir / name).read_bytes()).hexdigest() != expected:
                raise ValueError(f"Bundle checksum mismatch: {name}")
        self.domain_if = joblib.load(self.models_dir / "domain_isolation_forest.pkl")
        self.feature_scaler = joblib.load(self.models_dir / "feature_scaler.pkl")
        self.target_scaler = joblib.load(self.models_dir / "target_scaler.pkl")
        self.ridge_models = joblib.load(self.models_dir / "rvfl_ridge_models.pkl")
        # Load the trained random feature layers, rather than generating new ones.
        self.rvfl_orchestrator = joblib.load(self.models_dir / "rvfl_model.pkl")
        self.scenario_model = joblib.load(self.models_dir / "xgb_model.pkl")
        self.scenario_features = json.loads(
            (self.models_dir / "scenario_xgb_features.json").read_text(encoding="utf-8"))
        self.feature_columns = json.loads(
            (self.models_dir / "feature_columns_IF.json").read_text(encoding="utf-8"))
        self.scenario_names = self.config["scenario_names"]
        self.rvfl_metadata = {"sequence_length": self.config["sequence_length"]}
        self.if_weight = self.config["fusion_weights"]["isolation_forest"]
        self.xgb_weight = self.config["fusion_weights"]["xgboost"]
        self._explainer = None
        if not np.array_equal(self.scenario_model.classes_, np.arange(len(self.scenario_names))):
            raise ValueError("Scenario class ordering differs from the bundle contract.")

    def _raw_features(self, features):
        values = {}
        for name in self.feature_columns:
            value = features.get(name, 0.0)
            if value is None or (isinstance(value, (float, np.floating)) and np.isnan(value)):
                value = 0.0
            value = float(value)
            if not np.isfinite(value):
                raise ValueError(f"Nonfinite feature: {name}")
            values[name] = value
        return values

    def _enrich(self, daily_sequence):
        if not daily_sequence:
            raise ValueError("At least one observation is required.")
        dates = pd.to_datetime([day["date"] for day in daily_sequence], utc=True).normalize()
        if dates.hasnans or dates.duplicated().any():
            raise ValueError("Daily observations require unique valid UTC dates.")
        frame = pd.DataFrame([self._raw_features(day["features"]) for day in daily_sequence])
        frame["date"] = dates
        frame = frame.sort_values("date").reset_index(drop=True)
        matrices = [frame[columns].fillna(0).to_numpy() for columns in IF_GROUPS.values()]
        scores = self.domain_if.score(*matrices)
        for domain in IF_GROUPS:
            frame[f"{domain}_risk"] = scores[domain]
        frame["raw_overall_risk"] = sum(
            weight * frame[column] for column, weight in self.config["domain_weights"].items())
        frame["overall_risk"] = np.minimum(
            frame["raw_overall_risk"] / self.config["normalization_divisor"], 1.0)
        frame["daily_risk_delta"] = frame["overall_risk"].diff().fillna(0)
        frame["daily_risk_rolling_mean_7d"] = frame["overall_risk"].rolling(7, min_periods=1).mean()
        frame["daily_risk_rolling_std_7d"] = frame["overall_risk"].rolling(7, min_periods=1).std().fillna(0)
        return frame

    def _probabilities(self, frame):
        return self.scenario_model.predict_proba(frame[self.scenario_features].fillna(0))

    def _scenario_result(self, probabilities):
        winner = int(np.argmax(probabilities))
        return {"scenario": self.scenario_names[winner], "confidence": float(probabilities[winner]),
                **{f"rf_{name}_prob": float(probabilities[i])
                   for i, name in enumerate(self.scenario_names)}}

    def predict_current_risk(self, payload):
        frame = self._enrich([{"date": "2000-01-01", "features": payload["features"]}])
        row = frame.iloc[0]
        score = float(row.overall_risk)
        return {"detector": "isolation_forest", "overall_score": score,
                "raw_overall_risk": float(row.raw_overall_risk),
                "risk_level": "HIGH" if score >= .8 else "MEDIUM" if score >= .5 else "LOW",
                "domain_scores": {domain: float(row[f"{domain}_risk"]) for domain in IF_GROUPS}}

    def predict_scenario(self, payload):
        features = payload["features"]
        missing = set(self.scenario_features) - set(features)
        if missing:
            raise ValueError(f"Missing scenario features: {sorted(missing)}")
        frame = pd.DataFrame([{name: features[name] for name in self.scenario_features}])
        return self._scenario_result(self._probabilities(frame)[0])

    def predict_behavioral_risk(self, payload):
        """Compatibility API for caller-enriched observations; no SHAP without raw features."""
        days = payload["daily_sequence"]
        length = self.config["sequence_length"]
        if len(days) <= length:
            raise ValueError(f"daily_sequence must contain at least {length + 1} observations.")
        dates = pd.to_datetime([day["date"] for day in days], utc=True)
        if dates.hasnans or dates.duplicated().any():
            raise ValueError("Daily observations require unique valid dates.")
        days = [days[i] for i in np.argsort(dates)]
        fused = np.asarray([self.if_weight * float(day["overall_risk"]) + self.xgb_weight * max(
            float(day.get(f"rf_{name}_prob", 0)) for name in self.scenario_names[1:])
            for day in days], dtype=np.float32)
        if not np.isfinite(fused).all():
            raise ValueError("Nonfinite fused risk.")
        X_raw = np.asarray([fused[i-length:i, None] for i in range(length, len(days))], dtype=np.float32)
        X = self.feature_scaler.transform(X_raw.reshape(-1, 1)).reshape(X_raw.shape)
        y = self.target_scaler.transform(fused[length:, None]).ravel()
        with torch.no_grad():
            prediction = self.rvfl_orchestrator.predict(torch.tensor(X, dtype=torch.float32), self.ridge_models).ravel()
        errors = np.square(y - prediction)
        mean = float(errors.mean())
        thresholds = self.config["legacy_mean_error_thresholds"]
        level = "HIGH" if mean >= thresholds["high"] else "MEDIUM" if mean >= thresholds["medium"] else "LOW"
        scenario = max(self.scenario_names[1:], key=lambda name: float(days[-1].get(f"rf_{name}_prob", 0)))
        return {"payload_id": payload.get("payload_id"), "username": payload.get("username"),
                "hostname": payload.get("hostname"), "rvfl_error": float(errors[-1]),
                "behavioral_risk": level, "score_v2": float(errors.max()) * mean * float(np.sqrt(len(errors))),
                "sequence_length_received": len(days), "sequence_length_expected": length,
                "predicted_scenario": {"scenario": scenario, "confidence": float(days[-1].get(f"rf_{scenario}_prob", 0))},
                "model_versions": {"pipeline": self.config["model_version"]},
                "recommended_action": "Analyst review recommended." if level != "LOW" else "No action required.",
                "explanations": {"available": False, "reason": "Raw features required for SHAP."}}

    def _explain_dates(self, frame, probabilities, selected_indices):
        X = frame.iloc[selected_indices][self.scenario_features].fillna(0)
        with self._lock:
            if self._explainer is None:
                self._explainer = shap.TreeExplainer(
                    self.scenario_model, model_output="raw", feature_perturbation="tree_path_dependent")
            values = normalize_shap_values(
                self._explainer.shap_values(X), len(X), len(self.scenario_features), len(self.scenario_names))
            base = np.asarray(self._explainer.expected_value)
            margins = self.scenario_model.get_booster().predict(xgb.DMatrix(X), output_margin=True)
        residual = check_shap_additivity(values, base, margins)
        days = []
        for local_index, index in enumerate(selected_indices):
            probability = probabilities[index]
            threat = int(np.argmax(probability[1:]) + 1)
            winner = int(np.argmax(probability))
            classes = []
            prior_median = frame.iloc[max(0, index - 7):index][self.scenario_features].median()
            for class_index in dict.fromkeys([threat, winner]):
                items = [{
                    "feature": name, "observed_value": float(X.iloc[local_index][name]),
                    "normal_training_median": self.config["normal_training_medians"][name],
                    "preceding_7_observations_median": (
                        float(prior_median[name]) if len(prior_median) and np.isfinite(prior_median[name]) else None),
                    "shap_raw_margin": float(values[local_index, feature_index, class_index]),
                } for feature_index, name in enumerate(self.scenario_features)]
                items.sort(key=lambda item: abs(item["shap_raw_margin"]), reverse=True)
                classes.append({
                    "scenario": self.scenario_names[class_index],
                    "role": "selected_threat_for_risk_fusion" if class_index == threat else "predicted_class",
                    "probability": float(probability[class_index]),
                    "base_raw_margin": float(base[class_index]),
                    "sum_shap_raw_margin": float(values[local_index, :, class_index].sum()),
                    "output_raw_margin": float(margins[local_index, class_index]),
                    "positive_features": [item for item in items if item["shap_raw_margin"] > 0][:5],
                    "negative_features": [item for item in items if item["shap_raw_margin"] < 0][:5],
                    "all_features": items,
                })
            days.append({"date": frame.iloc[index]["date"].isoformat(),
                         "predicted_scenario": self.scenario_names[winner],
                         "xgboost_explanations": classes})
        return {"available": True, "explained_model": "XGBoost scenario raw margins",
                "explains_final_score_v2": False, "units": "raw margin, not probability points",
                "background": "tree-path training statistics, including SMOTE samples",
                "max_additivity_residual": residual, "key_dates": days}

    def predict_user_risk(self, payload, explain=True):
        frame = self._enrich(payload["daily_sequence"])
        probabilities = self._probabilities(frame)
        scenario_risk = probabilities[:, 1:].max(axis=1)
        fused = (self.if_weight * frame.overall_risk.to_numpy() + self.xgb_weight * scenario_risk)
        length = self.config["sequence_length"]
        count = len(frame) - length
        scenario = self._scenario_result(probabilities[-1])
        latest = frame.iloc[-1]
        current = {"overall_score": float(latest.overall_risk),
                   "raw_overall_risk": float(latest.raw_overall_risk),
                   "domain_scores": {domain: float(latest[f"{domain}_risk"]) for domain in IF_GROUPS}}
        errors = np.array([], dtype=float)
        daily_errors = []
        score_v2 = None
        components = None
        if count > 0:
            # Match create_sequences(): float32 before applying training-fitted scalers.
            X_raw = np.asarray([fused[i-length:i, None] for i in range(length, len(frame))], dtype=np.float32)
            y_raw = np.asarray(fused[length:, None], dtype=np.float32)
            X = self.feature_scaler.transform(X_raw.reshape(-1, 1)).reshape(X_raw.shape)
            y = self.target_scaler.transform(y_raw).ravel()
            with torch.no_grad():
                predictions = self.rvfl_orchestrator.predict(torch.tensor(X, dtype=torch.float32), self.ridge_models).ravel()
            errors = np.square(y - predictions)
            if not np.isfinite(errors).all():
                raise ValueError("RedRVFL produced nonfinite errors.")
            observed = self.target_scaler.inverse_transform(y.reshape(-1, 1)).ravel()
            predicted = self.target_scaler.inverse_transform(predictions.reshape(-1, 1)).ravel()
            maximum, mean = float(errors.max()), float(errors.mean())
            score_v2 = maximum * mean * float(np.sqrt(count))
            components = {"max_error": maximum, "mean_error": mean, "sequence_count": count,
                          "history_multiplier": float(np.sqrt(count)), "score_v2": score_v2,
                          "formula": self.config["score_formula"], "units": self.config["error_units"]}
            for i, error in enumerate(errors):
                daily_errors.append({"date": frame.iloc[i + length]["date"].isoformat(),
                    "error": float(error), "observed_risk_scaled": float(y[i]),
                    "predicted_risk_scaled": float(predictions[i]),
                    "observed_fused_risk": float(observed[i]), "predicted_fused_risk": float(predicted[i])})
            # Explain highest-error targets, not arbitrary dates or largest SHAP values.
            selected = sorted(range(count), key=lambda i: (-float(errors[i]), i))[:3]
            selected_indices = [i + length for i in selected]
            thresholds = self.config["legacy_mean_error_thresholds"]
            level = "HIGH" if mean >= thresholds["high"] else "MEDIUM" if mean >= thresholds["medium"] else "LOW"
            display = min(score_v2 * self.config["display_score"]["multiplier"], self.config["display_score"]["cap"])
            mode = "full_pipeline"
        else:
            selected_indices = [len(frame) - 1]
            level = "HIGH" if current["overall_score"] >= .8 else "MEDIUM" if current["overall_score"] >= .5 else "LOW"
            display = current["overall_score"] * 100
            mode = "if_xgb_warmup"
        evidence = {"available": False, "reason": "Explanations disabled."}
        if explain:
            try:
                evidence = self._explain_dates(frame, probabilities, selected_indices)
                errors_by_date = {row["date"]: row for row in daily_errors}
                for day in evidence["key_dates"]:
                    day.update(errors_by_date.get(day["date"], {}))
            except Exception as error:
                # Explanations must never change a valid detection score.
                evidence = {"available": False, "reason": f"{type(error).__name__}: {error}"}
        behavioral = {"rvfl_error": float(errors[-1]) if count > 0 else None,
                      "mean_error": float(errors.mean()) if count > 0 else None,
                      "behavioral_risk": level, "daily_errors": daily_errors,
                      "score_components": components}
        action = "Escalate for analyst review." if level == "HIGH" else "Monitor user behavior closely." if level == "MEDIUM" else "No action required."
        return {"payload_id": payload.get("payload_id"), "username": payload.get("username"),
                "hostname": payload.get("hostname"), "risk_score": float(display),
                "risk_level": level, "recommended_action": action,
                "score_v2": score_v2, "score_components": components, "mode": mode,
                "display_score_contract": self.config["display_score"] if count > 0 else {"description": "Warmup IF risk times 100; score_v2 unavailable."},
                "history": {"observations": len(frame), "sequence_count": max(count, 0),
                            "first_date": frame.iloc[0]["date"].isoformat(),
                            "last_date": latest["date"].isoformat(),
                            "scope": "supplied observations only; not necessarily consecutive calendar days"},
                "explanations": evidence,
                "detectors": {"isolation_forest": current, "xgboost": scenario, "red_rvfl": behavioral},
                "model_versions": {"pipeline": self.config["model_version"]},
                "sequence_length_received": len(frame), "sequence_length_expected": length}


_engine_lock = threading.Lock()


@lru_cache(maxsize=2)
def _cached_engine(directory, manifest_mtime):
    return InferenceEngine(directory)


def get_engine(models_dir=None):
    directory = Path(models_dir or Path(__file__).resolve().parents[3] / "artifacts/shap_v1").resolve()
    with _engine_lock:
        return _cached_engine(str(directory), (directory / "pipeline_config.json").stat().st_mtime_ns)


def predict_behavioral_risk(payload):
    return get_engine().predict_behavioral_risk(payload)


def predict_current_risk(payload):
    return get_engine().predict_current_risk(payload)


def predict_scenario(payload):
    return get_engine().predict_scenario(payload)


def predict_user_risk(payload):
    return get_engine().predict_user_risk(payload)

