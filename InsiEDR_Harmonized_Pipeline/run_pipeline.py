"""
InsiEDR Harmonized Telemetry Master Pipeline Runner
Executes 3-Tier Architecture on Candidate Harmonized Dataset:
- Tier 1: Domain Isolation Forest (Clean Background Training)
- Tier 2: Multi-Class XGBoost Scenario Classifier (Days 1 to 4 Primitives)
- Tier 3: Temporal Risk Fusion & Fleet Workstation Triage Ranking

Strict Anti-Leakage Controls:
- Ascending chronological sort
- Half-open [start_time, end_time) indexing
- Zero SYNTHETIC_ONLY cheat features
- Train (D1-4) vs Val (D5) vs Test (D6-7)
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from src.data_loader import (
    load_manifest,
    clean_collector_data,
    label_collector_evidence,
    get_train_val_test_splits,
    DATA_DIR
)
from src.domain_isolation_forest import DomainIsolationForest
from src.scenario_classifier_xgb import ScenarioXGBClassifier
from src.temporal_risk_aggregator import TemporalRiskAggregator

OUTPUT_DIR = os.path.join(current_dir, "output")
MODELS_DIR = os.path.join(current_dir, "models")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

def main():
    print("=" * 80)
    print("   INSIEDR PIPELINE EVALUATION ON HARMONIZED TELEMETRY")
    print("=" * 80)

    manifest = load_manifest()
    meta = manifest["dataset_metadata"]
    print(f"Dataset: {meta['title']}")
    print(f"Fleet Workstations: {meta['total_physical_workstations']} | Duration: {meta['duration_hours']}h")
    print(f"Data Directory: {DATA_DIR}\n")

    # Target hosts for strict disjointness check
    train_target_hosts = {"SOCL2-64", "DSL-174", "DATASL-173", "MCALAB1-07", "SOCL8-53"}
    test_target_hosts = {"SOCL8-03", "SOCL4-61"}

    # We evaluate on the core active endpoint collectors:
    # 1. short-term_edr_feature (Auth velocity, unique workstations, off-hours - present across all 7 scenarios)
    # 2. lsass-monitor (Credential dumping, handle queries)
    # 3. process-watcher (Admin and temp executables)
    # 4. file-integrity-monitor (File modifications, staging)
    # 5. decoy-monitor (Canary trap interactions)

    collectors_to_evaluate = [
        "short-term_edr_feature",
        "lsass-monitor",
        "process-watcher",
        "decoy-monitor"
    ]

    all_feed_results = {}

    for cname in collectors_to_evaluate:
        print("\n" + "=" * 70)
        print(f"PROCESSING COLLECTOR FEED: {cname.upper()}")
        print("=" * 70)

        # Find CSV
        files = [f for f in os.listdir(DATA_DIR) if f.startswith(cname + "_dataset_") and f.endswith(".csv")]
        if not files:
            print(f"Warning: No file found for {cname}")
            continue
        csv_path = os.path.join(DATA_DIR, files[0])

        print(f"Loading {csv_path}...")
        raw_df = pd.read_csv(csv_path, low_memory=False)
        print(f"Raw rows: {len(raw_df):,}")

        # Clean & strip SYNTHETIC_ONLY cheat features
        df_clean, feat_cols = clean_collector_data(raw_df, cname)
        print(f"Clean behavioral features ({len(feat_cols)} cols): {feat_cols}")

        # Label evidence-bearing rows under half-open [start, end)
        df_labeled = label_collector_evidence(df_clean, cname, manifest)
        threat_count = df_labeled["is_threat"].sum()
        print(f"Labeled evidence rows: {threat_count:,} ({threat_count / len(df_labeled):.2%})")

        # Chronological Partitioning
        train_df, val_df, test_df = get_train_val_test_splits(df_labeled)
        print(f"Splits -> Train (D1-4): {len(train_df):,} | Val (D5): {len(val_df):,} | Test (D6-7): {len(test_df):,}")

        # Verify host disjointness
        train_threats = train_df[train_df["is_threat"] == 1]["hostname"].unique()
        test_threats = test_df[test_df["is_threat"] == 1]["hostname"].unique()
        print(f"  Train Threat Hosts: {list(train_threats)}")
        print(f"  Test Threat Hosts:  {list(test_threats)}")
        overlap = set(train_threats).intersection(set(test_threats))
        assert len(overlap) == 0, f"Host leakage detected! {overlap}"
        print("  Host Disjointness Check: PASSED (Zero Entity Overlap)")

        # Prepare X, y
        X_train = train_df[feat_cols].values
        y_train_bin = train_df["is_threat"].values
        y_train_scen = train_df["scenario_class"].values

        X_val = val_df[feat_cols].values
        y_val_bin = val_df["is_threat"].values

        X_test = test_df[feat_cols].values
        y_test_bin = test_df["is_threat"].values
        y_test_scen = test_df["scenario_class"].values

        # -------------------------------------------------------------
        # TIER 1: DOMAIN ISOLATION FOREST
        # -------------------------------------------------------------
        print("\n--- [Tier 1] Fitting Domain Isolation Forest on Clean Background ---")
        clean_train_mask = ~train_df["hostname"].isin(train_target_hosts)
        X_train_clean = X_train[clean_train_mask]
        print(f"Fitting on {len(X_train_clean):,} clean records across {train_df.loc[clean_train_mask, 'hostname'].nunique()} background hosts...")

        dom_if = DomainIsolationForest(contamination=0.03)
        dom_if.fit(X_train_clean)

        train_anomaly_scores = dom_if.score_anomaly(X_train)
        val_anomaly_scores = dom_if.score_anomaly(X_val)
        test_anomaly_scores = dom_if.score_anomaly(X_test)

        val_alarm_rate = (dom_if.predict(X_val) == 1).mean()
        print(f"Validation (Day 5 clean baseline) False Alarm Rate: {val_alarm_rate:.2%}")

        # -------------------------------------------------------------
        # TIER 2: SCENARIO CLASSIFIER (XGBOOST)
        # -------------------------------------------------------------
        print("\n--- [Tier 2] Training XGBoost Scenario Classifier ---")
        xgb_clf = ScenarioXGBClassifier()
        xgb_clf.fit(X_train, y_train_scen)

        test_scenario_preds = xgb_clf.predict(X_test)
        test_scenario_probs = xgb_clf.get_max_threat_prob(X_test)

        # -------------------------------------------------------------
        # TIER 3: TEMPORAL RISK FUSION & WORKSTATION RANKING
        # -------------------------------------------------------------
        print("\n--- [Tier 3] Fusing Multi-Tier Risk & Ranking Workstations ---")
        risk_agg = TemporalRiskAggregator(if_weight=0.3, xgb_weight=0.7)
        test_df["anomaly_score"] = test_anomaly_scores
        test_df["scenario_prob"] = test_scenario_probs
        test_df["fused_risk"] = risk_agg.fuse_risk(test_anomaly_scores, test_scenario_probs)

        ranked_hosts = risk_agg.rank_workstations(test_df)
        print("\nTop 10 Workstation Triage Queue (Test Days 6-7):")
        print(ranked_hosts.head(10)[["rank", "hostname", "is_threat_host", "threat_scenario", "max_risk", "host_score"]])

        top_k_eval = risk_agg.evaluate_top_k(ranked_hosts, ks=[1, 2, 3, 5, 10, 20])
        print("\nTop-K Review Queue Metrics across 216 Fleet Workstations:")
        print(top_k_eval.to_string(index=False))

        # Save artifacts
        ranked_hosts.to_csv(os.path.join(OUTPUT_DIR, f"{cname}_test_host_rankings.csv"), index=False)
        top_k_eval.to_csv(os.path.join(OUTPUT_DIR, f"{cname}_top_k_evaluation.csv"), index=False)

        all_feed_results[cname] = {
            "features": feat_cols,
            "test_hosts_evaluated": len(ranked_hosts),
            "threat_hosts_in_test": int(ranked_hosts["is_threat_host"].sum()),
            "threat_host_ranks": {
                r["hostname"]: int(r["rank"]) for _, r in ranked_hosts[ranked_hosts["is_threat_host"] == 1].iterrows()
            },
            "top_k_metrics": top_k_eval.to_dict(orient="records")
        }

    # Save summary json
    with open(os.path.join(OUTPUT_DIR, "pipeline_summary.json"), "w", encoding="utf-8") as f:
        json.dump(all_feed_results, f, indent=2)

    print("\n" + "=" * 80)
    print("PIPELINE EXECUTION COMPLETED SUCCESSFULLY!")
    print(f"Results saved to: {OUTPUT_DIR}")
    print("=" * 80)

if __name__ == "__main__":
    main()
