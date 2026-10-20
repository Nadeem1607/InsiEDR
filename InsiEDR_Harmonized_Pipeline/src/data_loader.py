"""
InsiEDR Harmonized Telemetry Data Loader & Feature Ingestion Module
Strict compliance with:
- ML_DATASET_GUIDE.md (Ascending sort, half-open [start, end) intervals)
- FEATURE_DICTIONARY.md (SYNTHETIC_ONLY feature stripping, no label leakage)
- simulation_manifest.json (Evidence-bearing row masking, chronological splitting)
"""

import os
import glob
import json
import pandas as pd
import numpy as np

DATA_DIR = r"d:\AISH\Dataset_Simulated_Harmonized\Dataset_Simulated_Harmonized"
MANIFEST_PATH = os.path.join(DATA_DIR, "simulation_manifest.json")

# Ground truth scenario classes for multi-class XGBoost
SCENARIO_CLASS_MAP = {
    "BENIGN": 0,
    "CREDENTIAL_DUMP": 1,
    "USB_EXFILTRATION_PRECURSOR": 2,
    "IT_SABOTAGE": 3,
    "CLOUD_EXFILTRATION_PRECURSOR": 4,
    "DATA_HOARDING": 5,
    "HONEYTOKEN_TRIP": 6,
    "KILL_CHAIN_APT": 7,
}

# Features that MUST be stripped to prevent trivial shortcut learning / label leakage
SYNTHETIC_ONLY_FEATURES = {
    "credential_dumping_suspected",
    "mimikatz_signatures",
    "threat_triggered",
    "unauthorized_usb_detected",
    "lateral_movement_suspected",
    "modifications_detected",
    "post_requests",
    "large_uploads",
    "sample_threats",
    "note",
}

def load_manifest():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def clean_collector_data(df, collector_name):
    """
    Standardizes timestamp, sorts ascending, and strips SYNTHETIC_ONLY cheat features.
    """
    # 1. Uniform timestamp parsing & chronological sort
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"].astype(str).str.slice(0, 19))
    df = df.sort_values("timestamp_dt").reset_index(drop=True)

    # 2. Envelope & metadata columns
    envelope_cols = ["timestamp", "timestamp_dt", "username", "hostname", "agent_id", "status"]
    
    # 3. Select clean behavioral numeric features
    feature_cols = []
    for col in df.columns:
        if col in envelope_cols or col in SYNTHETIC_ONLY_FEATURES:
            continue
        
        # Convert boolean objects to numeric float
        if df[col].dtype == object or df[col].dtype == bool:
            try:
                converted = df[col].map({"True": 1.0, "False": 0.0, True: 1.0, False: 0.0}).fillna(df[col])
                numeric_series = pd.to_numeric(converted, errors="coerce")
                if not numeric_series.isna().all():
                    df[col] = numeric_series.fillna(0.0)
                    feature_cols.append(col)
            except Exception:
                pass
        elif np.issubdtype(df[col].dtype, np.number):
            df[col] = df[col].fillna(0.0)
            feature_cols.append(col)

    return df, feature_cols

def label_collector_evidence(df, collector_name, manifest):
    """
    Applies strict half-open [start_time, end_time) phase-aware row labeling.
    A row is positive ONLY during active scenario phases for that collector.
    """
    df["is_threat"] = 0
    df["scenario_class"] = 0
    df["scenario_id"] = "BENIGN"

    for sc in manifest["scenarios"]:
        sc_id = sc["scenario_id"]
        class_id = SCENARIO_CLASS_MAP.get(sc["multiclass_label"], 0)
        target_host = sc["target_hostname"]

        # Check if scenario has multi-phase breakdown (SIM_KILL_CHAIN)
        if "phases" in sc:
            for phase in sc["phases"]:
                if collector_name in phase.get("active_collectors", []):
                    p_start = pd.to_datetime(phase["start_time"])
                    p_end = pd.to_datetime(phase["end_time"])
                    mask = (
                        (df["hostname"] == target_host) &
                        (df["timestamp_dt"] >= p_start) &
                        (df["timestamp_dt"] < p_end)
                    )
                    df.loc[mask, "is_threat"] = 1
                    df.loc[mask, "scenario_class"] = class_id
                    df.loc[mask, "scenario_id"] = sc_id
        else:
            if collector_name in sc.get("injected_collectors", []):
                s_start = pd.to_datetime(sc["start_time"])
                s_end = pd.to_datetime(sc["end_time"])
                mask = (
                    (df["hostname"] == target_host) &
                    (df["timestamp_dt"] >= s_start) &
                    (df["timestamp_dt"] < s_end)
                )
                df.loc[mask, "is_threat"] = 1
                df.loc[mask, "scenario_class"] = class_id
                df.loc[mask, "scenario_id"] = sc_id

    return df

def get_train_val_test_splits(df):
    """
    Chronological partitioning:
    - Train: Days 1 to 4 (< 2026-10-10 00:00:00)
    - Val:   Day 5 (2026-10-10 00:00:00 to 2026-10-11 00:00:00 - Saturday)
    - Test:  Days 6 to 7 (>= 2026-10-11 00:00:00)
    """
    t_val = pd.to_datetime("2026-10-10 00:00:00")
    t_test = pd.to_datetime("2026-10-11 00:00:00")

    train_df = df[df["timestamp_dt"] < t_val].copy().reset_index(drop=True)
    val_df = df[(df["timestamp_dt"] >= t_val) & (df["timestamp_dt"] < t_test)].copy().reset_index(drop=True)
    test_df = df[df["timestamp_dt"] >= t_test].copy().reset_index(drop=True)

    return train_df, val_df, test_df
