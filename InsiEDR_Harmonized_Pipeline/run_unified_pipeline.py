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
from src.temporal_risk_aggregator import TemporalRiskAggregator
from src.red_rvfl_orchestrator import RedRVFLOrchestrator
from src.shap_explainer import InsiEDRShapExplainer
import joblib

OUTPUT_DIR = os.path.join(current_dir, "output")
MODELS_DIR = os.path.join(current_dir, "models")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

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

    # Container for all scored test and train observations across feeds
    all_train_scored_records = []
    all_test_scored_records = []
    test_dfs_by_feed = {}
    feed_summaries = {}
    shap_explainer = InsiEDRShapExplainer()

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

        # Collect scored train split for Tier 3 RedRVFL
        train_anom = dom_if.score_anomaly(X_train)
        train_scen = xgb_clf.get_max_threat_prob(X_train)
        train_df["feed"] = cname
        train_df["anomaly_score"] = train_anom
        train_df["scenario_prob"] = train_scen
        train_df["fused_risk"] = np.maximum(train_anom, 0.3 * train_anom + 0.7 * train_scen)
        all_train_scored_records.append(train_df[keep_cols].copy())
        test_dfs_by_feed[cname] = test_df.copy()

        # Register feed into Tier 2 TreeSHAP Explainer
        shap_explainer.register_feed(cname, xgb_clf, feat_cols, train_df[clean_train_mask], dom_if=dom_if)

        # 4. Save trained models to models/ directory
        if_model_name = f"{cname}_domain_if.joblib"
        xgb_model_name = f"{cname}_scenario_xgb.joblib"
        joblib.dump(dom_if, os.path.join(MODELS_DIR, if_model_name))
        joblib.dump(xgb_clf, os.path.join(MODELS_DIR, xgb_model_name))

        elapsed = time.time() - t0
        threats_in_test = test_df[test_df["is_threat"] == 1]["hostname"].unique().tolist()
        print(f"[{cname:23s}] Evaluated in {elapsed:4.1f}s | Clean Val False Alarms: {val_alarm_rate:5.2%} | Test Threat Hosts: {threats_in_test}")

        feed_summaries[cname] = {
            "features_used": feat_cols,
            "num_features": len(feat_cols),
            "val_false_alarm_rate": float(val_alarm_rate),
            "test_threat_hosts": threats_in_test,
            "isolation_forest_model": if_model_name,
            "scenario_xgb_model": xgb_model_name
        }

    # Save models manifest
    with open(os.path.join(MODELS_DIR, "models_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(feed_summaries, f, indent=2)

    # -------------------------------------------------------------
    # TIER 3: DEEP RedRVFL NEURAL TEMPORAL SEQUENCE MODELING
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TIER 3: TRAINING DEEP RedRVFL ON CLEAN BASELINE SEQUENCES")
    print("=" * 80)

    unified_train_df = pd.concat(all_train_scored_records, ignore_index=True)
    unified_test_df = pd.concat(all_test_scored_records, ignore_index=True)
    print(f"Total scored train observations across 8 feeds: {len(unified_train_df):,}")
    print(f"Total scored test observations across 8 feeds:  {len(unified_test_df):,}")

    risk_agg = TemporalRiskAggregator(if_weight=0.3, xgb_weight=0.7, seq_len=5, hidden_size=64, num_layers=3, ridge_alpha=0.01)
    clean_bg_hosts = set(unified_train_df["hostname"].unique()) - train_target_hosts
    print(f"Fitting RedRVFL on clean sequences from {len(clean_bg_hosts)} background workstations...")
    risk_agg.fit_red_rvfl(unified_train_df, clean_hosts=clean_bg_hosts)

    print("Evaluating Tier 3 RedRVFL Sequence Drift Forecasting on Test Fleet...")
    redrvfl_drift_df = risk_agg.predict_red_rvfl_drift(unified_test_df)

    # Save Tier 3 RedRVFL model
    rvfl_model_name = "tier3_red_rvfl_orchestrator.joblib"
    joblib.dump(risk_agg.red_rvfl, os.path.join(MODELS_DIR, rvfl_model_name))
    print(f"Saved Tier 3 RedRVFL model to: {os.path.join(MODELS_DIR, rvfl_model_name)}")

    feed_summaries["tier3_red_rvfl"] = {
        "model_type": "Deep RedRVFL (Random Vector Functional Link)",
        "feature_extractor": "RandomLSTM",
        "hidden_size": 64,
        "num_layers": 3,
        "sequence_length": 5,
        "ridge_alpha": 0.01,
        "model_file": rvfl_model_name,
        "clean_training_hosts": len(clean_bg_hosts),
        "test_sequences_evaluated": len(redrvfl_drift_df)
    }

    # Resave models manifest with RedRVFL included
    with open(os.path.join(MODELS_DIR, "models_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(feed_summaries, f, indent=2)

    # Workstation-level multi-domain aggregation with RedRVFL sequence drift
    ranked_fleet = risk_agg.rank_workstations(unified_test_df, redrvfl_drift_df=redrvfl_drift_df)

    # Identify triggered feeds per host
    feed_peaks_per_host = unified_test_df.groupby(["hostname", "feed"])["fused_risk"].max().reset_index()
    triggered_map = {}
    for host, grp in feed_peaks_per_host.groupby("hostname"):
        trig = grp.loc[grp["fused_risk"] >= 0.3, "feed"].tolist()
        triggered_map[host] = ", ".join(trig) if trig else "None"
    ranked_fleet["triggered_feeds"] = ranked_fleet["hostname"].map(triggered_map).fillna("None")

    print("\n" + "=" * 95)
    print("TOP 15 FLEET WORKSTATION TRIAGE QUEUE (WITH TIER 3 RedRVFL DRIFT)")
    print("=" * 95)
    cols_to_print = ["rank", "hostname", "is_threat_host", "threat_scenario", "peak_fused_risk", "rvfl_max_drift_error", "high_risk_ticks", "host_score", "triggered_feeds"]
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

    # -------------------------------------------------------------
    # TIER 4: LOCAL TreeSHAP EXPLAINABILITY ENGINE
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TIER 4: EXPLAINING FLAGGED EVENTS & TRIAGE QUEUE VIA LOCAL TreeSHAP")
    print("=" * 80)

    # Serialize SHAP explainer
    shap_model_name = "tier2_shap_explainer.joblib"
    joblib.dump(shap_explainer, os.path.join(MODELS_DIR, shap_model_name))
    print(f"Saved Tier 2 SHAP Explainer model to: {os.path.join(MODELS_DIR, shap_model_name)}")

    feed_summaries["tier2_shap_explainer"] = {
        "model_file": shap_model_name,
        "registered_feeds": shap_explainer.registered_feeds,
        "explainer_type": "TreeSHAP_Local_Margins",
        "mathematical_contract": "base_margin + sum(shap_values) == output_margin"
    }
    with open(os.path.join(MODELS_DIR, "models_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(feed_summaries, f, indent=2)

    print("Generating signed SHAP explanations for top triage queue hosts and flagged events...")
    workstation_explanations = shap_explainer.explain_workstation_incidents(
        ranked_fleet,
        test_dfs_by_feed,
        top_n_hosts=10,
        max_events_per_feed=2
    )
    shap_explainer.export_explanations(workstation_explanations, OUTPUT_DIR)

    print("\n" + "=" * 90)
    print("EXPLICIT SHAP EVIDENCE: TOP FLAGGED THREAT WORKSTATIONS")
    print("=" * 90)
    for host in workstation_explanations[:2]:
        print(f"\n[HOST: {host['hostname']}] Rank #{host['rank']} | Threat: {host['threat_scenario']} | Score: {host['host_score']:.2f} | RedRVFL Drift: {host['rvfl_drift_error']:.6f}")
        for ev in host["explained_events"]:
            feed = ev["feed"]
            s_ev = ev["shap_evidence"]
            scen = s_ev.get("predicted_scenario", "N/A")
            prob = s_ev.get("scenario_probability", ev["scenario_prob"])
            print(f"  > Feed: {feed:24s} | Fused: {ev['fused_risk']:.4f} | Scenario: {scen} ({prob:.2%})")
            if "base_raw_margin" in s_ev:
                print(f"    Margin: Base {s_ev['base_raw_margin']:.4f} + Sum(SHAP) {s_ev['sum_shap_raw_margin']:+.4f} = Output {s_ev['output_raw_margin']:.4f} (Res: {s_ev['additivity_residual']:1.2e})")
            top_feats = s_ev.get("top_features", [])[:3]
            for tf in top_feats:
                s_val = tf.get("shap_raw_margin", tf.get("deviation", 0.0))
                print(f"      - {tf['feature']:28s} | Observed: {tf['observed_value']:8.2f} | Normal Median: {tf['normal_training_median']:8.2f} | SHAP: {s_val:+8.4f} ({tf.get('direction', tf.get('impact', ''))})")

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
        "top_k_table": eval_records,
        "shap_explanations": {
            "summary_json": os.path.join(OUTPUT_DIR, "explanations", "flagged_events_shap_summary.json"),
            "attributions_csv": os.path.join(OUTPUT_DIR, "explanations", "flagged_events_shap_attributions.csv"),
            "report_markdown": os.path.join(OUTPUT_DIR, "explanations", "SHAP_EXPLANATIONS_REPORT.md"),
            "findings_txt": os.path.join(OUTPUT_DIR, "explanations", "SHAP_FINDINGS.txt")
        }
    }

    with open(os.path.join(OUTPUT_DIR, "unified_pipeline_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 80)
    print("UNIFIED MULTI-FEED PIPELINE EXECUTION COMPLETED!")
    print(f"Results saved to: {OUTPUT_DIR}")
    print("=" * 80)

if __name__ == "__main__":
    main()
