"""
InsiEDR Unified Multi-Feed Cross-Domain Correlator
Executes full cross-domain threat correlation across 8 core endpoint sensor feeds:
1. short-term_edr_feature (Auth velocity, unique workstations - All Scenarios)
2. decoy-monitor (Canary Honeytoken Access - SOCL8-03, SOCL4-61)
3. logon (Authentication & After-Hours Bursts - SOCL8-03)
4. lsass-monitor (OS Credential Dumping - SOCL2-64, SOCL4-61)
5. process-watcher (Admin & Temp Executables - SOCL2-64, DATASL-173)
6. devices (USB Exfiltration Precursor - DSL-174)
7. file-integrity-monitor (Mass Deletion & Staging - DATASL-173, SOCL8-53, SOCL4-61)
8. http (Cloud Exfiltration Precursor - MCALAB1-07, SOCL4-61)

Combines multi-tier risk (0.3 IF + 0.7 XGB) per feed, applies non-linear domain max-pooling
to prevent linear score stacking, and ranks all 216 workstations in the fleet.
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np

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

OUTPUT_DIR = os.path.join(current_dir, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

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

def main():
    print("=" * 80)
    print("   INSIEDR UNIFIED MULTI-FEED CROSS-DOMAIN CORRELATOR")
    print("=" * 80)

    manifest = load_manifest()
    meta = manifest["dataset_metadata"]
    print(f"Target Fleet: {meta['total_physical_workstations']} Physical Workstations")
    print(f"Duration: {meta['duration_hours']} hours | Feeds in Evaluation Suite: {len(CORE_FEEDS)}\n")

    train_target_hosts = {"SOCL2-64", "DSL-174", "DATASL-173", "MCALAB1-07", "SOCL8-53"}
    test_target_hosts = {"SOCL8-03", "SOCL4-61"}

    # Container for all scored test observations across feeds
    all_test_scored_records = []
    feed_summaries = {}

    start_total_time = time.time()

    for cname in CORE_FEEDS:
        t0 = time.time()
        files = [f for f in os.listdir(DATA_DIR) if f.startswith(cname + "_dataset_") and f.endswith(".csv")]
        if not files:
            print(f"Warning: File missing for {cname}")
            continue
        csv_path = os.path.join(DATA_DIR, files[0])

        # Load & Clean
        raw_df = pd.read_csv(csv_path, low_memory=False)
        df_clean, feat_cols = clean_collector_data(raw_df, cname)

        # Label evidence
        df_labeled = label_collector_evidence(df_clean, cname, manifest)

        # Split Chronologically
        train_df, val_df, test_df = get_train_val_test_splits(df_labeled)

        # Prepare matrices
        X_train = train_df[feat_cols].values
        y_train_scen = train_df["scenario_class"].values

        X_val = val_df[feat_cols].values
        X_test = test_df[feat_cols].values

        # 1. Tier 1: Domain Isolation Forest (fit on clean training background hosts)
        clean_train_mask = ~train_df["hostname"].isin(train_target_hosts)
        X_train_clean = X_train[clean_train_mask]

        dom_if = DomainIsolationForest(contamination=0.03)
        dom_if.fit(X_train_clean)
        test_anomaly_scores = dom_if.score_anomaly(X_test)
        val_alarm_rate = (dom_if.predict(X_val) == 1).mean()


        # 2. Tier 2: Scenario XGBoost Classifier
        xgb_clf = ScenarioXGBClassifier()
        xgb_clf.fit(X_train, y_train_scen)
        test_scenario_probs = xgb_clf.get_max_threat_prob(X_test)

        # 3. Tier 3 Feed Fusion: Adaptive Fusion
        # If a feed detects a novel/zero-shot anomaly, avoid suppressing the anomaly score with dead-weight zero scenario probabilities.
        fused_risk = np.maximum(test_anomaly_scores, 0.3 * test_anomaly_scores + 0.7 * test_scenario_probs)

        test_df["feed"] = cname
        test_df["anomaly_score"] = test_anomaly_scores
        test_df["scenario_prob"] = test_scenario_probs
        test_df["fused_risk"] = fused_risk

        # Keep relevant columns for cross-domain aggregation
        keep_cols = ["timestamp_dt", "hostname", "feed", "is_threat", "scenario_id", "fused_risk", "anomaly_score", "scenario_prob"]
        scored_subset = test_df[keep_cols].copy()
        all_test_scored_records.append(scored_subset)

        elapsed = time.time() - t0
        threats_in_test = test_df[test_df["is_threat"] == 1]["hostname"].unique().tolist()
        print(f"[{cname:23s}] Evaluated in {elapsed:4.1f}s | Clean Val False Alarms: {val_alarm_rate:5.2%} | Test Threat Hosts: {threats_in_test}")

        feed_summaries[cname] = {
            "features_used": len(feat_cols),
            "val_false_alarm_rate": float(val_alarm_rate),
            "test_threat_hosts": threats_in_test
        }

    # Concatenate all scored test records
    print("\n" + "=" * 80)
    print("FUSING MULTI-DOMAIN RISK SIGNALS ACROSS FLEET WORKSTATIONS")
    print("=" * 80)

    unified_test_df = pd.concat(all_test_scored_records, ignore_index=True)
    print(f"Total scored test observations across 8 feeds: {len(unified_test_df):,}")

    # Workstation-level multi-domain aggregation
    # Non-linear correlation: Anti-stacking max-pool across domains + duration accumulation
    host_triage_records = []
    all_hosts = unified_test_df["hostname"].unique()

    for host in all_hosts:
        h_df = unified_test_df[unified_test_df["hostname"] == host]
        
        is_threat = int(h_df["is_threat"].max())
        threat_scenarios = h_df.loc[h_df["is_threat"] == 1, "scenario_id"].unique().tolist()
        threat_scenario_name = ", ".join(threat_scenarios) if threat_scenarios else "BENIGN"

        # Per-feed peak risks on this host
        feed_peaks = h_df.groupby("feed")["fused_risk"].max().to_dict()

        # Non-linear multi-domain risk (Max across domains prevents artificial linear stacking)
        peak_fused_risk = float(h_df["fused_risk"].max())
        mean_fused_risk = float(h_df["fused_risk"].mean())
        
        # High-risk ticks across any feed (ticks where risk >= 0.3)
        high_risk_ticks = int((h_df["fused_risk"] >= 0.3).sum())

        # Persistent host score: peak * mean * sqrt(high_risk_ticks)
        host_score = peak_fused_risk * (mean_fused_risk + 0.001) * np.sqrt(max(high_risk_ticks, 1))

        # Identify which feeds triggered on this host
        triggered_feeds = [f for f, r in feed_peaks.items() if r >= 0.3]

        host_triage_records.append({
            "hostname": host,
            "is_threat_host": is_threat,
            "threat_scenario": threat_scenario_name,
            "total_telemetry_ticks": len(h_df),
            "high_risk_ticks": high_risk_ticks,
            "peak_fused_risk": round(peak_fused_risk, 4),
            "mean_fused_risk": round(mean_fused_risk, 4),
            "triggered_feeds": ", ".join(triggered_feeds) if triggered_feeds else "None",
            "host_score": round(host_score, 4)
        })

    # Sort Workstations by composite host score
    ranked_fleet = pd.DataFrame(host_triage_records).sort_values("host_score", ascending=False).reset_index(drop=True)
    ranked_fleet["rank"] = ranked_fleet.index + 1

    print("\n" + "=" * 90)
    print("TOP 15 FLEET WORKSTATION TRIAGE QUEUE (OUT-OF-TIME TEST SPLIT: DAYS 6 TO 7)")
    print("=" * 90)
    cols_to_print = ["rank", "hostname", "is_threat_host", "threat_scenario", "peak_fused_risk", "high_risk_ticks", "host_score", "triggered_feeds"]
    print(ranked_fleet.head(15)[cols_to_print].to_string(index=False))

    # Evaluate Top-K Review Queue Metrics across Fleet
    total_threat_hosts = int(ranked_fleet["is_threat_host"].sum())
    total_fleet_hosts = len(ranked_fleet)

    eval_records = []
    for k in [1, 2, 3, 5, 10, 20]:
        top_k = ranked_fleet.head(k)
        tp = int(top_k["is_threat_host"].sum())
        fp = k - tp
        fn = total_threat_hosts - tp
        recall = tp / total_threat_hosts if total_threat_hosts > 0 else 0.0
        precision = tp / k
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        eval_records.append({
            "Top_K_Reviewed": k,
            "Workforce_Pct": f"{round((k / total_fleet_hosts) * 100, 2)}%",
            "Threats_Caught": f"{tp} / {total_threat_hosts}",
            "False_Alarms": fp,
            "Recall": f"{round(recall * 100, 2)}%",
            "Precision": f"{round(precision * 100, 2)}%",
            "F1_Score": round(f1, 4)
        })

    eval_df = pd.DataFrame(eval_records)
    print("\n" + "=" * 90)
    print("UNIFIED TOP-K REVIEW QUEUE EVALUATION METRICS (FLEET-WIDE)")
    print("=" * 90)
    print(eval_df.to_string(index=False))

    # Save to output CSVs
    ranked_fleet.to_csv(os.path.join(OUTPUT_DIR, "unified_fleet_triage_rankings.csv"), index=False)
    eval_df.to_csv(os.path.join(OUTPUT_DIR, "unified_top_k_evaluation.csv"), index=False)

    # Save complete JSON summary
    summary = {
        "execution_time_seconds": round(time.time() - start_total_time, 2),
        "total_test_hosts": total_fleet_hosts,
        "total_threat_hosts": total_threat_hosts,
        "threat_host_ranks": {
            r["hostname"]: {
                "rank": int(r["rank"]),
                "scenario": r["threat_scenario"],
                "score": float(r["host_score"]),
                "triggered_feeds": r["triggered_feeds"]
            }
            for _, r in ranked_fleet[ranked_fleet["is_threat_host"] == 1].iterrows()
        },
        "top_k_table": eval_records
    }

    with open(os.path.join(OUTPUT_DIR, "unified_pipeline_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 80)
    print("UNIFIED MULTI-FEED PIPELINE EXECUTION COMPLETED!")
    print(f"Results saved to: {OUTPUT_DIR}")
    print("=" * 80)

if __name__ == "__main__":
    main()
