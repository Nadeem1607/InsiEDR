"""Export the exact trained pipeline, including inference numerical contracts."""
import hashlib
import json
import shutil
from importlib.metadata import version
from pathlib import Path

import numpy as np


ARTIFACTS = (
    "domain_isolation_forest.pkl", "xgb_model.pkl", "rvfl_model.pkl",
    "rvfl_ridge_models.pkl", "feature_scaler.pkl", "target_scaler.pkl",
)


def export_model_bundle(output_dir, destination, features, labels, train_users,
                        feature_columns, normalization_divisor, domain_weights):
    output_dir, destination = Path(output_dir), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if not np.isfinite(normalization_divisor) or normalization_divisor <= 0:
        raise ValueError("Risk normalization requires a positive training-only divisor.")
    normal_users = set(labels.loc[labels.is_insider == 0, "user_id"]) & set(train_users)
    normal = features[features.user.isin(normal_users)]
    if normal.empty:
        raise ValueError("No normal training observations for explanation references.")
    checksums = {}
    for name in ARTIFACTS:
        source = output_dir / name
        shutil.copy2(source, destination / name)
        checksums[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    (destination / "scenario_xgb_features.json").write_text(
        json.dumps(list(feature_columns), indent=2), encoding="utf-8")
    raw_columns = [name for name in feature_columns if name not in {
        "logon_risk", "file_risk", "device_risk", "http_risk", "overall_risk",
        "raw_overall_risk", "daily_risk_delta", "daily_risk_rolling_mean_7d",
        "daily_risk_rolling_std_7d",
    }]
    (destination / "feature_columns_IF.json").write_text(
        json.dumps(raw_columns, indent=2), encoding="utf-8")
    config = {
        "schema_version": 1, "model_version": "shap-train-only-if-v1",
        "domain_weights": domain_weights, "normalization_divisor": float(normalization_divisor),
        "fusion_weights": {"isolation_forest": 0.3, "xgboost": 0.7},
        "sequence_length": 7,
        "scenario_names": ["normal", "email_exfil", "sabotage", "usb_exfil", "flight_risk", "cloud_exfil"],
        "score_formula": "max_error * mean_error * sqrt(sequence_count)",
        "error_units": "squared target-scaled fused-risk error",
        "display_score": {"multiplier": 1000.0, "cap": 100.0,
                          "description": "Compatibility adapter, not a probability or calibrated severity."},
        "legacy_mean_error_thresholds": {"medium": 0.02, "high": 0.05},
        "normal_training_medians": {name: float(value) for name, value in
                                     normal[feature_columns].fillna(0).median().items()},
        "if_fit_boundary": {"scope": "training_users_only", "train_users": len(set(train_users)),
                            "fitted_rows": int(features.user.isin(train_users).sum()),
                            "excluded_rows": int((~features.user.isin(train_users)).sum())},
        "versions": {name: version(name) for name in (
            "numpy", "pandas", "scikit-learn", "torch", "xgboost", "shap", "joblib")},
        "sha256": checksums,
    }
    config["sha256"]["scenario_xgb_features.json"] = hashlib.sha256(
        (destination / "scenario_xgb_features.json").read_bytes()).hexdigest()
    config["sha256"]["feature_columns_IF.json"] = hashlib.sha256(
        (destination / "feature_columns_IF.json").read_bytes()).hexdigest()
    # Write the manifest last so an incomplete export is not advertised as ready.
    (destination / "pipeline_config.json").write_text(
        json.dumps(config, indent=2, allow_nan=False), encoding="utf-8")
    print(f"Exported complete SHAP inference bundle to '{destination}'.")
    return config
