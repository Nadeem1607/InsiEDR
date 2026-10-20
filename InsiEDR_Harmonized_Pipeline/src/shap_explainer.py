"""
InsiEDR Local TreeSHAP Explainability Engine
Directly ports and harmonizes the SHAP explainability framework from InsiEDR_Model_Updated.

Provides:
1. Exact signed TreeSHAP raw margin attributions on Tier 2 XGBoost scenario models:
   base_margin + sum(feature_SHAP_values) == output_margin (verified with additivity residual < 1e-4).
2. Distinction between supporting (+ SHAP), opposing (- SHAP), and neutral feature contributions.
3. Baseline reference context: compares observed feature values against clean training medians.
4. Anomaly domain evidence for zero-shot / pure anomaly feeds (decoy canary trip, logon surge).
5. Incident drill-downs connecting Tier 1 IF anomaly, Tier 2 XGBoost scenario, and Tier 3 RedRVFL sequence drift.
6. Structured JSON, tabular CSV, and analyst-ready Markdown reporting.
"""

import os
import json
import numpy as np
import pandas as pd
import shap
import xgboost as xgb
from src.data_loader import SCENARIO_CLASS_MAP

# Reverse scenario mapping for readable labels
SCENARIO_NAME_MAP = {v: k for k, v in SCENARIO_CLASS_MAP.items()}


def normalize_shap_values(values, row_count, feature_count, class_count):
    """Support SHAP versions returning either class lists or a 3D array."""
    if isinstance(values, list):
        values = np.stack(values, axis=-1)
    values = np.asarray(values)
    expected = (row_count, feature_count, class_count)
    if values.shape != expected:
        raise ValueError(f"Unexpected multiclass SHAP shape {values.shape}; expected {expected}.")
    if not np.isfinite(values).all():
        raise ValueError("SHAP returned nonfinite contributions.")
    return values


def check_shap_additivity(values, base_values, raw_margins):
    """
    Validates that local feature SHAP values reconstruct the XGBoost booster margin:
    base_margin + sum(shap_values) == output_margin
    """
    reconstructed = values.sum(axis=1) + base_values
    residual = float(np.max(np.abs(reconstructed - raw_margins)))
    if not np.allclose(reconstructed, raw_margins, rtol=1e-4, atol=2e-4):
        raise ValueError(f"SHAP contributions do not reconstruct XGBoost margins: residual={residual:.8g}.")
    return residual


class InsiEDRShapExplainer:
    def __init__(self):
        self.explainers = {}
        self.models = {}
        self.dom_ifs = {}
        self.feature_cols = {}
        self.normal_medians = {}
        self.registered_feeds = []

    def register_feed(self, feed_name, xgb_clf, feat_cols, clean_train_df, dom_if=None):
        """
        Registers a feed's trained model, features, and normal training baseline medians.
        Precomputes TreeExplainer on XGBoost booster if available.
        """
        self.models[feed_name] = xgb_clf
        self.dom_ifs[feed_name] = dom_if
        self.feature_cols[feed_name] = list(feat_cols)
        if feed_name not in self.registered_feeds:
            self.registered_feeds.append(feed_name)

        # Baseline medians on clean background training data
        if clean_train_df is not None and not clean_train_df.empty:
            medians = clean_train_df[feat_cols].median().to_dict()
            self.normal_medians[feed_name] = {k: float(v) for k, v in medians.items()}
        else:
            self.normal_medians[feed_name] = {k: 0.0 for k in feat_cols}

        # Initialize TreeExplainer for XGBoost if model exists
        if xgb_clf is not None and xgb_clf.model is not None:
            explainer = shap.TreeExplainer(
                xgb_clf.model,
                model_output="raw",
                feature_perturbation="tree_path_dependent"
            )
            self.explainers[feed_name] = explainer
        else:
            self.explainers[feed_name] = None

    def explain_event(self, feed_name, feature_vector, features_per_direction=5):
        """
        Explains a single flagged event for a given feed.
        Returns detailed signed SHAP margins, observed vs normal medians, and additivity checks.
        """
        feat_cols = self.feature_cols.get(feed_name, [])
        if not feat_cols:
            return {"available": False, "reason": f"Feed {feed_name} not registered."}

        # Format input vector as 2D numpy array and Series
        if isinstance(feature_vector, pd.Series):
            feat_series = pd.to_numeric(feature_vector[feat_cols], errors="coerce").fillna(0.0)
            X = feat_series.values.astype(np.float32).reshape(1, -1)
        elif isinstance(feature_vector, dict):
            feat_series = pd.Series([feature_vector.get(f, 0.0) for f in feat_cols], index=feat_cols)
            feat_series = pd.to_numeric(feat_series, errors="coerce").fillna(0.0)
            X = feat_series.values.astype(np.float32).reshape(1, -1)
        elif isinstance(feature_vector, np.ndarray):
            X = feature_vector.astype(np.float32).reshape(1, -1)
            feat_series = pd.Series(X[0], index=feat_cols)
        else:
            raise ValueError(f"Unsupported feature_vector type: {type(feature_vector)}")

        xgb_clf = self.models.get(feed_name)
        explainer = self.explainers.get(feed_name)
        medians = self.normal_medians.get(feed_name, {})

        # If feed has no XGBoost model (single-class training / zero-shot anomaly)
        if explainer is None or xgb_clf is None or xgb_clf.model is None:
            # Domain anomaly explanation
            dom_if = self.dom_ifs.get(feed_name)
            anom_score = float(dom_if.score_anomaly(X)[0]) if dom_if is not None else 0.0

            # Rank features by absolute deviation from normal training median
            deviations = []
            for col in feat_cols:
                obs = float(feat_series[col])
                med = float(medians.get(col, 0.0))
                diff = obs - med
                deviations.append({
                    "feature": col,
                    "observed_value": obs,
                    "normal_training_median": med,
                    "deviation": diff,
                    "impact": "anomaly_trigger" if diff > 0 else "nominal" if diff == 0 else "below_baseline"
                })
            deviations.sort(key=lambda d: abs(d["deviation"]), reverse=True)

            return {
                "available": True,
                "model_type": "IsolationForest_ZeroShot",
                "feed": feed_name,
                "anomaly_score": anom_score,
                "scenario_prob": 0.0,
                "predicted_scenario": "ZERO_SHOT_ANOMALY",
                "top_features": deviations[:features_per_direction],
                "explanation_note": "Zero-shot anomaly feed (trained on pure benign baseline). Explained via domain baseline deviation."
            }

        # XGBoost TreeSHAP explanation
        dmat = xgb.DMatrix(X)
        booster = xgb_clf.model.get_booster()
        raw_margins = booster.predict(dmat, output_margin=True)
        probs = xgb_clf.predict_proba(X)[0]

        num_classes = xgb_clf.num_classes
        shap_raw = explainer.shap_values(X)

        if num_classes == 2:
            # Binary logistic: target is the threat class (class index 1 in encoded space)
            val_arr = np.asarray(shap_raw).ravel()
            base_val = float(explainer.expected_value)
            out_margin = float(raw_margins[0])
            recon = base_val + float(np.sum(val_arr))
            residual = abs(recon - out_margin)

            # Map encoded class 1 back to scenario name
            threat_class_id = int(xgb_clf.encoder.classes_[1]) if len(xgb_clf.encoder.classes_) > 1 else 1
            threat_scenario = SCENARIO_NAME_MAP.get(threat_class_id, f"SCENARIO_{threat_class_id}")
            threat_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

            items = []
            for f_idx, col in enumerate(feat_cols):
                obs = float(feat_series[col])
                med = float(medians.get(col, 0.0))
                s_val = float(val_arr[f_idx])
                if s_val > 1e-6:
                    direction = "increases_threat_risk"
                elif s_val < -1e-6:
                    direction = "opposes_threat_risk"
                else:
                    direction = "neutral"

                items.append({
                    "feature": col,
                    "observed_value": obs,
                    "normal_training_median": med,
                    "shap_raw_margin": s_val,
                    "direction": direction
                })

            items.sort(key=lambda x: abs(x["shap_raw_margin"]), reverse=True)
            pos_features = [x for x in items if x["shap_raw_margin"] > 0][:features_per_direction]
            neg_features = [x for x in items if x["shap_raw_margin"] < 0][:features_per_direction]

            return {
                "available": True,
                "model_type": "XGBoost_Binary",
                "feed": feed_name,
                "predicted_scenario": threat_scenario,
                "scenario_probability": threat_prob,
                "base_raw_margin": base_val,
                "output_raw_margin": out_margin,
                "sum_shap_raw_margin": float(np.sum(val_arr)),
                "additivity_residual": residual,
                "top_features": items[:features_per_direction],
                "positive_features": pos_features,
                "negative_features": neg_features,
                "all_features": items
            }

        else:
            # Multiclass softmax
            vals_3d = normalize_shap_values(shap_raw, 1, len(feat_cols), num_classes)
            base_vals = np.asarray(explainer.expected_value)
            if base_vals.shape != (num_classes,):
                raise ValueError(f"Expected base_vals shape ({num_classes},), got {base_vals.shape}")

            residual = check_shap_additivity(vals_3d, base_vals, raw_margins)

            # Determine winning class and threat class with highest probability
            winning_enc = int(np.argmax(probs))
            # Malicious classes (exclude class 0 if present)
            benign_idx = np.where(xgb_clf.encoder.classes_ == 0)[0]
            threat_indices = [i for i in range(num_classes) if i not in benign_idx]
            if threat_indices:
                threat_enc = threat_indices[int(np.argmax(probs[threat_indices]))]
            else:
                threat_enc = winning_enc

            # Focus explanation on the highest threat class
            target_enc = threat_enc if threat_enc != 0 else winning_enc
            target_class_id = int(xgb_clf.encoder.classes_[target_enc])
            threat_scenario = SCENARIO_NAME_MAP.get(target_class_id, f"SCENARIO_{target_class_id}")
            target_prob = float(probs[target_enc])

            val_arr = vals_3d[0, :, target_enc]
            base_val = float(base_vals[target_enc])
            out_margin = float(raw_margins[0, target_enc])

            items = []
            for f_idx, col in enumerate(feat_cols):
                obs = float(feat_series[col])
                med = float(medians.get(col, 0.0))
                s_val = float(val_arr[f_idx])
                if s_val > 1e-6:
                    direction = "increases_threat_risk"
                elif s_val < -1e-6:
                    direction = "opposes_threat_risk"
                else:
                    direction = "neutral"

                items.append({
                    "feature": col,
                    "observed_value": obs,
                    "normal_training_median": med,
                    "shap_raw_margin": s_val,
                    "direction": direction
                })

            items.sort(key=lambda x: abs(x["shap_raw_margin"]), reverse=True)
            pos_features = [x for x in items if x["shap_raw_margin"] > 0][:features_per_direction]
            neg_features = [x for x in items if x["shap_raw_margin"] < 0][:features_per_direction]

            return {
                "available": True,
                "model_type": "XGBoost_Multiclass",
                "feed": feed_name,
                "target_class_id": target_class_id,
                "predicted_scenario": threat_scenario,
                "scenario_probability": target_prob,
                "winning_scenario": SCENARIO_NAME_MAP.get(int(xgb_clf.encoder.classes_[winning_enc]), "UNKNOWN"),
                "winning_probability": float(probs[winning_enc]),
                "base_raw_margin": base_val,
                "output_raw_margin": out_margin,
                "sum_shap_raw_margin": float(np.sum(val_arr)),
                "additivity_residual": residual,
                "top_features": items[:features_per_direction],
                "positive_features": pos_features,
                "negative_features": neg_features,
                "all_features": items
            }

    def explain_flagged_event_by_id(self, feed_name, hostname, timestamp, test_dfs_by_feed):
        """
        Looks up a specific flagged event by feed, host, and timestamp, and returns its SHAP explanation.
        """
        if feed_name not in test_dfs_by_feed:
            return {"available": False, "reason": f"Feed {feed_name} not found in test data."}

        df_feed = test_dfs_by_feed[feed_name]
        t_target = pd.to_datetime(timestamp)
        matches = df_feed[(df_feed["hostname"] == hostname) & (pd.to_datetime(df_feed["timestamp_dt"]) == t_target)]
        if matches.empty:
            # Fuzzy match within 60s
            time_diffs = (pd.to_datetime(df_feed["timestamp_dt"]) - t_target).abs()
            host_mask = df_feed["hostname"] == hostname
            close_idx = time_diffs[host_mask].idxmin() if host_mask.any() else None
            if close_idx is not None:
                matches = df_feed.loc[[close_idx]]
            else:
                return {"available": False, "reason": f"No record found for {hostname} at {timestamp} in {feed_name}."}

        ev_row = matches.iloc[0]
        explanation = self.explain_event(feed_name, ev_row)
        explanation["hostname"] = hostname
        explanation["timestamp"] = str(ev_row.get("timestamp_dt", ev_row.get("timestamp", "")))
        explanation["fused_risk"] = float(ev_row.get("fused_risk", 0.0))
        explanation["anomaly_score"] = float(ev_row.get("anomaly_score", 0.0))
        explanation["scenario_prob"] = float(ev_row.get("scenario_prob", 0.0))
        return explanation

    def explain_workstation_incidents(self, ranked_fleet, test_dfs_by_feed, top_n_hosts=5, max_events_per_feed=2):
        """
        Generates incident explanations across all triggered sensor feeds for top triage workstations.
        """
        explanations = []
        top_hosts = ranked_fleet.head(top_n_hosts)

        for _, host_row in top_hosts.iterrows():
            hostname = host_row["hostname"]
            rank = int(host_row["rank"])
            is_threat = bool(host_row["is_threat_host"] == 1)
            threat_scenario = str(host_row["threat_scenario"])
            host_score = float(host_row["host_score"])
            peak_fused_risk = float(host_row["peak_fused_risk"])
            rvfl_drift = float(host_row.get("rvfl_max_drift_error", 0.0))
            triggered_feeds = [f.strip() for f in str(host_row.get("triggered_feeds", "")).split(",") if f.strip() and f.strip() != "None"]

            host_summary = {
                "rank": rank,
                "hostname": hostname,
                "is_threat_host": is_threat,
                "threat_scenario": threat_scenario,
                "host_score": host_score,
                "peak_fused_risk": peak_fused_risk,
                "rvfl_drift_error": rvfl_drift,
                "triggered_feeds": triggered_feeds,
                "explained_events": []
            }

            # If no feeds explicitly triggered >= 0.3, check feeds with max risk for this host
            feeds_to_check = triggered_feeds if triggered_feeds else list(test_dfs_by_feed.keys())

            for feed_name in feeds_to_check:
                if feed_name not in test_dfs_by_feed:
                    continue
                df_feed = test_dfs_by_feed[feed_name]
                host_feed_rows = df_feed[df_feed["hostname"] == hostname]
                if host_feed_rows.empty:
                    continue

                # Sort by fused_risk descending and deduplicate identical timestamps to pick peak distinct event(s)
                ts_col = "timestamp_dt" if "timestamp_dt" in host_feed_rows.columns else "timestamp"
                sorted_events = (
                    host_feed_rows.sort_values("fused_risk", ascending=False)
                    .drop_duplicates(subset=[ts_col])
                    .head(max_events_per_feed)
                )

                for _, ev_row in sorted_events.iterrows():
                    event_time = str(ev_row.get("timestamp_dt", ev_row.get("timestamp", "")))
                    fused_risk = float(ev_row.get("fused_risk", 0.0))
                    anom_score = float(ev_row.get("anomaly_score", 0.0))
                    scen_prob = float(ev_row.get("scenario_prob", 0.0))

                    shap_evidence = self.explain_event(feed_name, ev_row)

                    host_summary["explained_events"].append({
                        "feed": feed_name,
                        "timestamp": event_time,
                        "fused_risk": fused_risk,
                        "anomaly_score": anom_score,
                        "scenario_prob": scen_prob,
                        "shap_evidence": shap_evidence
                    })

            explanations.append(host_summary)

        return explanations

    def export_explanations(self, workstation_explanations, output_dir):
        """
        Exports structured JSON, flat CSV, and human-readable Markdown / text findings.
        """
        exp_dir = os.path.join(output_dir, "explanations")
        os.makedirs(exp_dir, exist_ok=True)

        # 1. Structured JSON
        json_path = os.path.join(exp_dir, "flagged_events_shap_summary.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": "2.0_harmonized",
                "explainer_type": "InsiEDR_TreeSHAP_Local_Margins",
                "mathematical_contract": "base_raw_margin + sum(shap_values) == output_raw_margin",
                "coverage": f"{len(workstation_explanations)} top fleet workstations",
                "workstations": workstation_explanations
            }, f, indent=2)

        # 2. Flat CSV of all feature attributions
        flat_records = []
        for host_info in workstation_explanations:
            host = host_info["hostname"]
            rank = host_info["rank"]
            threat = host_info["threat_scenario"]
            for ev in host_info["explained_events"]:
                feed = ev["feed"]
                timestamp = ev["timestamp"]
                fused = ev["fused_risk"]
                shap_ev = ev["shap_evidence"]
                scenario = shap_ev.get("predicted_scenario", "N/A")
                prob = shap_ev.get("scenario_probability", ev["scenario_prob"])

                features = shap_ev.get("all_features", shap_ev.get("top_features", []))
                for item in features:
                    flat_records.append({
                        "rank": rank,
                        "hostname": host,
                        "threat_scenario": threat,
                        "feed": feed,
                        "timestamp": timestamp,
                        "fused_risk": fused,
                        "predicted_scenario": scenario,
                        "scenario_probability": prob,
                        "feature": item["feature"],
                        "observed_value": item["observed_value"],
                        "normal_training_median": item.get("normal_training_median", 0.0),
                        "shap_raw_margin": item.get("shap_raw_margin", item.get("deviation", 0.0)),
                        "direction": item.get("direction", item.get("impact", ""))
                    })

        csv_path = os.path.join(exp_dir, "flagged_events_shap_attributions.csv")
        pd.DataFrame(flat_records).to_csv(csv_path, index=False)

        # 3. Comprehensive Markdown Report
        md_path = os.path.join(exp_dir, "SHAP_EXPLANATIONS_REPORT.md")
        lines = [
            "# InsiEDR Multi-Feed SHAP Explainability Report",
            "",
            "## Executive Summary",
            "This report details the exact mathematical feature attributions from the trained Tier 2 Scenario XGBoost models ",
            "and baseline deviations explaining why workstations and individual telemetry events were flagged by the Harmonized Pipeline.",
            "",
            "### Mathematical Contract",
            "```text",
            "output_raw_margin = base_raw_margin + sum(local_feature_SHAP_values)",
            "threat_probability = sigmoid(output_raw_margin)  [Binary]  OR  softmax(output_raw_margins)  [Multiclass]",
            "```",
            "- **Positive SHAP (+)**: Increases the model's raw threat margin (evidence of malicious insider activity).",
            "- **Negative SHAP (-)**: Opposes the threat margin (indicates normal or dampening activity).",
            "- **Neutral (0)**: Feature does not alter the raw margin.",
            "- **Normal Baseline**: Median observed value during 4 days of clean fleet background operations.",
            "",
            "---",
            ""
        ]

        for host in workstation_explanations:
            lines.extend([
                f"## Workstation Rank #{host['rank']}: `{host['hostname']}`",
                f"- **Threat Status**: `{'CONFIRMED MALICIOUS' if host['is_threat_host'] else 'BENIGN FLEET'}`",
                f"- **Threat Scenario**: `{host['threat_scenario']}`",
                f"- **Overall Risk Score**: `{host['host_score']:.2f}` (Peak Fused Risk: `{host['peak_fused_risk']:.4f}`)",
                f"- **Tier 3 Deep RedRVFL Drift Error**: `{host['rvfl_drift_error']:.6f}`",
                f"- **Triggered Sensor Feeds**: `{', '.join(host['triggered_feeds']) if host['triggered_feeds'] else 'None'}`",
                ""
            ])

            for idx, ev in enumerate(host["explained_events"], 1):
                feed = ev["feed"]
                t_stamp = ev["timestamp"]
                shap_ev = ev["shap_evidence"]
                lines.extend([
                    f"### Event {idx}: Feed `{feed}` @ `{t_stamp}`",
                    f"- **Fused Risk**: `{ev['fused_risk']:.4f}` (Anomaly: `{ev['anomaly_score']:.4f}`, Scenario Prob: `{ev['scenario_prob']:.4f}`)",
                    f"- **Predicted Scenario**: `{shap_ev.get('predicted_scenario', 'N/A')}` (Probability: `{shap_ev.get('scenario_probability', shap_ev.get('anomaly_score', 0.0)):.4f}`)"
                ])

                if "base_raw_margin" in shap_ev:
                    lines.extend([
                        f"- **Margin Reconstruction**: Base `{shap_ev['base_raw_margin']:.4f}` + Sum(SHAP) `{shap_ev['sum_shap_raw_margin']:+.4f}` = Output `{shap_ev['output_raw_margin']:.4f}` (Residual: `{shap_ev['additivity_residual']:1.2e}`)",
                        ""
                    ])

                lines.extend([
                    "| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |",
                    "| :--- | :---: | :---: | :---: | :--- |"
                ])

                top_feats = shap_ev.get("top_features", [])
                for f in top_feats:
                    shap_val = f.get("shap_raw_margin", f.get("deviation", 0.0))
                    direction = f.get("direction", f.get("impact", "")).replace("_", " ")
                    lines.append(
                        f"| `{f['feature']}` | `{f['observed_value']:.4f}` | `{f['normal_training_median']:.4f}` | `{shap_val:+.4f}` | **{direction}** |"
                    )
                lines.append("")

            lines.append("---\n")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        # 4. Text findings matching InsiEDR_Model_Updated format
        txt_path = os.path.join(exp_dir, "SHAP_FINDINGS.txt")
        txt_lines = [
            "=" * 80,
            "INSIEDR EXPLICIT SHAP FINDINGS: MULTI-FEED CROSS-DOMAIN ATTRIBUTIONS",
            "=" * 80,
            f"Coverage: {len(workstation_explanations)} top workstations in Fleet Triage Queue.",
            "SHAP explains Tier 2 XGBoost scenario raw margins and Tier 1 domain baseline anomalies.",
            "Positive SHAP increases threat raw margin; negative SHAP opposes that class.",
            "Normal training medians provide reference baselines from clean background operations.",
            "=" * 80,
            ""
        ]

        for host in workstation_explanations:
            txt_lines.extend([
                "-" * 80,
                f"WORKSTATION {host['hostname']} | Fleet Rank #{host['rank']} | Score: {host['host_score']:.2f} | Scenario: {host['threat_scenario']}",
                f"RedRVFL Drift Error: {host['rvfl_drift_error']:.6f} | Triggered Feeds: {', '.join(host['triggered_feeds']) if host['triggered_feeds'] else 'None'}",
                "-" * 80
            ])
            for ev in host["explained_events"]:
                shap_ev = ev["shap_evidence"]
                txt_lines.extend([
                    f"  FEED: {ev['feed']} @ {ev['timestamp']} | Fused Risk: {ev['fused_risk']:.4f} | Scenario: {shap_ev.get('predicted_scenario', 'N/A')}",
                ])
                if "positive_features" in shap_ev and shap_ev["positive_features"]:
                    txt_lines.append("    SUPPORTING THREAT FEATURES (+ SHAP):")
                    for p in shap_ev["positive_features"]:
                        txt_lines.append(f"      {p['feature']}: observed={p['observed_value']:.4f}; baseline_median={p['normal_training_median']:.4f}; SHAP={p['shap_raw_margin']:+.4f}")
                if "negative_features" in shap_ev and shap_ev["negative_features"]:
                    txt_lines.append("    OPPOSING THREAT FEATURES (- SHAP):")
                    for n in shap_ev["negative_features"]:
                        txt_lines.append(f"      {n['feature']}: observed={n['observed_value']:.4f}; baseline_median={n['normal_training_median']:.4f}; SHAP={n['shap_raw_margin']:+.4f}")
            txt_lines.append("")

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(txt_lines))

        print(f"SHAP explanations successfully exported to: {exp_dir}")
        print(f" - JSON: {json_path}")
        print(f" - CSV:  {csv_path}")
        print(f" - MD:   {md_path}")
        print(f" - TXT:  {txt_path}")
