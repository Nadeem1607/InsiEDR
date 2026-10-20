"""
InsiEDR Telemetry Feature Variance & Invariant Analyzer
Calculates statistical variance across clean background workstations over the 5-day baseline period (Days 1 to 5).
Identifies:
1. Zero-Variance Invariants (sigma == 0.0): Security tripwires, canary indicators, and silent counters.
2. Active Dynamic Features (sigma > 0.0): Fluctuating daily operational behavioral gauges.
"""

import os
import sys
import numpy as np
import pandas as pd

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from src.data_loader import clean_collector_data, DATA_DIR

CORE_FEEDS = [
    "short-term_edr_feature",
    "decoy-monitor",
    "logon",
    "lsass-monitor",
    "process-watcher",
    "devices",
    "file-integrity-monitor",
    "http"
]

train_target_hosts = {"SOCL2-64", "DSL-174", "DATASL-173", "MCALAB1-07", "SOCL8-53"}
cutoff_5day = pd.to_datetime("2026-10-11 00:00:00")
OUTPUT_DIR = os.path.join(current_dir, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def compute_fleet_feature_variances():
    results = []
    print("=" * 80)
    print("COMPUTING 5-DAY BASELINE FEATURE VARIANCES (DAYS 1 TO 5 - CLEAN FLEET)")
    print("=" * 80)

    for cname in CORE_FEEDS:
        files = [f for f in os.listdir(DATA_DIR) if f.startswith(cname + "_dataset_") and f.endswith(".csv")]
        if not files:
            continue
        csv_path = os.path.join(DATA_DIR, files[0])
        raw_df = pd.read_csv(csv_path, low_memory=False)
        df_clean, feat_cols = clean_collector_data(raw_df, cname)

        mask_5day = (df_clean["timestamp_dt"] < cutoff_5day) & (~df_clean["hostname"].isin(train_target_hosts))
        df_baseline = df_clean[mask_5day]

        total_rows = len(df_baseline)
        unique_hosts = df_baseline["hostname"].nunique()

        for col in feat_cols:
            vals = df_baseline[col].values
            v_mean = float(np.nanmean(vals))
            v_std = float(np.nanstd(vals))
            v_var = float(np.nanvar(vals))
            v_min = float(np.nanmin(vals))
            v_max = float(np.nanmax(vals))

            is_zero_var = np.isclose(v_var, 0.0)

            if is_zero_var:
                category = "ZERO_VARIANCE (Constant Invariant)"
            elif v_std < 0.1:
                category = "LOW_VARIANCE (Rare / Low Scale)"
            else:
                category = "ACTIVE_VARIANCE (Dynamic Fluctuations)"

            results.append({
                "feed": cname,
                "feature": col,
                "mean": round(v_mean, 4),
                "std": round(v_std, 4),
                "variance": round(v_var, 6),
                "min": round(v_min, 4),
                "max": round(v_max, 4),
                "category": category,
                "total_samples": total_rows,
                "clean_hosts": unique_hosts
            })

    summary_df = pd.DataFrame(results)
    out_csv = os.path.join(OUTPUT_DIR, "feature_variance_5day_baseline.csv")
    summary_df.to_csv(out_csv, index=False)
    print(f"\nAnalysis complete across {len(summary_df)} features. Saved to: {out_csv}")
    return summary_df

if __name__ == "__main__":
    compute_fleet_feature_variances()
