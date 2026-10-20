"""
Tier 3: InsiEDR Deep RedRVFL Temporal Sequence Modeler & Workstation Triage Aggregator Module

Responsibilities:
1. Dual-Path Adaptive Risk Fusion:
   fused_risk = max(Tier 1 Anomaly Score, 0.3 * Anomaly + 0.7 * Scenario Probability)
2. RedRVFL Neural Sequence Forecasting:
   Multi-layer RandomLSTM with skip-connections and Ridge ensemble.
   Learns normal behavioral dynamics over temporal sequences [t - W, t).
3. Forecasting Drift Error Scoring:
   |y - y_hat| captures temporal sequence breakdown during attacks.
4. Fleet-Wide Workstation Triage Ranking.
"""

import numpy as np
import pandas as pd
import torch
import joblib
from src.red_rvfl_orchestrator import RedRVFLOrchestrator

class TemporalRiskAggregator:
    def __init__(self, if_weight=0.3, xgb_weight=0.7, seq_len=5, hidden_size=64, num_layers=3, ridge_alpha=0.01):
        self.if_weight = if_weight
        self.xgb_weight = xgb_weight
        self.seq_len = seq_len
        self.red_rvfl = RedRVFLOrchestrator(
            input_features=1,
            hidden_size=hidden_size,
            num_layers=num_layers,
            ridge_alpha=ridge_alpha
        )
        self.rvfl_fitted = False

    def fuse_risk(self, anomaly_scores, scenario_probs):
        """
        Combines Tier 1 anomaly scores and Tier 2 scenario probabilities using adaptive dual-path fusion.
        Ensures novel/zero-day attacks where scenario probability is 0 are not suppressed.
        """
        anom = np.asarray(anomaly_scores, dtype=float)
        scen = np.asarray(scenario_probs, dtype=float)
        weighted = self.if_weight * anom + self.xgb_weight * scen
        return np.maximum(anom, weighted)

    def build_sliding_sequences(self, df, time_bin_freq="10min"):
        """
        Groups telemetry by workstation and regular temporal bins, constructing sliding sequences [t-W, t).
        """
        df_copy = df.copy()
        if not pd.api.types.is_datetime64_any_dtype(df_copy["timestamp_dt"]):
            df_copy["timestamp_dt"] = pd.to_datetime(df_copy["timestamp_dt"])
        
        df_copy["time_bin"] = df_copy["timestamp_dt"].dt.floor(time_bin_freq)
        
        # Max-pool risk across domains per time-bin
        agg_dict = {"fused_risk": "max"}
        if "is_threat" in df_copy.columns:
            agg_dict["is_threat"] = "max"
        if "scenario_id" in df_copy.columns:
            agg_dict["scenario_id"] = "first"
        
        bin_df = df_copy.groupby(["hostname", "time_bin"]).agg(agg_dict).reset_index()
        
        X, y, meta = [], [], []
        for host, group in bin_df.groupby("hostname"):
            group = group.sort_values("time_bin").reset_index(drop=True)
            risks = group["fused_risk"].values
            times = group["time_bin"].values
            is_th = group["is_threat"].values if "is_threat" in group.columns else np.zeros(len(group))
            scens = group["scenario_id"].values if "scenario_id" in group.columns else ["BENIGN"] * len(group)

            if len(risks) <= self.seq_len:
                continue
            for i in range(self.seq_len, len(risks)):
                X.append(risks[i - self.seq_len : i].reshape(self.seq_len, 1))
                y.append(risks[i])
                meta.append({
                    "hostname": host,
                    "time_bin": times[i],
                    "is_threat": is_th[i],
                    "scenario_id": scens[i],
                    "actual_risk": risks[i]
                })

        return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32), meta

    def fit_red_rvfl(self, train_df, clean_hosts=None, time_bin_freq="10min"):
        """
        Fits Tier 3 RedRVFL strictly on normal/clean background workstation sequences.
        """
        if clean_hosts is not None:
            clean_mask = train_df["hostname"].isin(clean_hosts)
            target_df = train_df[clean_mask].copy()
        else:
            target_df = train_df.copy()

        X_train_seq, y_train_seq, _ = self.build_sliding_sequences(target_df, time_bin_freq=time_bin_freq)
        if len(X_train_seq) > 0:
            self.red_rvfl.fit(X_train_seq, y_train_seq)
            self.rvfl_fitted = True
        return self

    def predict_red_rvfl_drift(self, test_df, time_bin_freq="10min"):
        """
        Calculates RedRVFL neural forecasting sequence error on test data.
        """
        if not self.rvfl_fitted:
            raise ValueError("RedRVFL must be fitted before scoring drift.")

        X_test_seq, y_test_seq, meta_test = self.build_sliding_sequences(test_df, time_bin_freq=time_bin_freq)
        if len(X_test_seq) == 0:
            return pd.DataFrame()

        preds = self.red_rvfl.predict(X_test_seq)
        drift_errors = self.red_rvfl.compute_sequence_error(X_test_seq, y_test_seq)

        results_df = pd.DataFrame(meta_test)
        results_df["forecasted_risk"] = preds
        results_df["drift_error"] = drift_errors
        return results_df

    def rank_workstations(self, df_scored, redrvfl_drift_df=None):
        """
        Aggregates fused risk and RedRVFL temporal sequence drift per workstation:
        Returns ranked DataFrame of workstations.
        """
        records = []
        rvfl_stats = {}
        if redrvfl_drift_df is not None and len(redrvfl_drift_df) > 0:
            for host, group in redrvfl_drift_df.groupby("hostname"):
                max_err = float(group["drift_error"].max())
                mean_err = float(group["drift_error"].mean())
                high_err_ticks = int((group["drift_error"] >= 0.3).sum())
                rvfl_stats[host] = {
                    "max_drift_error": max_err,
                    "mean_drift_error": mean_err,
                    "high_err_ticks": high_err_ticks,
                    "rvfl_score": max_err * (mean_err + 0.001) * np.sqrt(max(high_err_ticks, 1))
                }

        for host, group in df_scored.groupby("hostname"):
            risks = group["fused_risk"].values
            is_threat_host = int(group["is_threat"].max())
            scens = group.loc[group["is_threat"] == 1, "scenario_id"].unique().tolist()
            threat_scenario = ", ".join(scens) if scens else "BENIGN"
            
            high_risk_ticks = (risks >= 0.3).sum()
            max_r = float(np.max(risks))
            mean_r = float(np.mean(risks))
            
            # Persistent host triage score
            base_score = max_r * (mean_r + 0.001) * np.sqrt(max(high_risk_ticks, 1))
            
            host_rec = {
                "hostname": host,
                "is_threat_host": is_threat_host,
                "threat_scenario": threat_scenario,
                "total_ticks": len(risks),
                "high_risk_ticks": int(high_risk_ticks),
                "peak_fused_risk": round(max_r, 4),
                "mean_fused_risk": round(mean_r, 4),
                "host_score": round(base_score, 4)
            }

            if host in rvfl_stats:
                host_rec["rvfl_max_drift_error"] = round(rvfl_stats[host]["max_drift_error"], 4)
                host_rec["rvfl_mean_drift_error"] = round(rvfl_stats[host]["mean_drift_error"], 4)
                host_rec["rvfl_score"] = round(rvfl_stats[host]["rvfl_score"], 4)
            else:
                host_rec["rvfl_max_drift_error"] = 0.0
                host_rec["rvfl_mean_drift_error"] = 0.0
                host_rec["rvfl_score"] = 0.0

            records.append(host_rec)

        ranked_df = pd.DataFrame(records).sort_values("host_score", ascending=False).reset_index(drop=True)
        ranked_df["rank"] = ranked_df.index + 1
        return ranked_df

    def evaluate_top_k(self, ranked_df, ks=[1, 3, 5, 10, 20]):
        """
        Computes Top-K review queue evaluation metrics across fleet workstations.
        """
        total_threat_hosts = int(ranked_df["is_threat_host"].sum())
        total_hosts = len(ranked_df)

        eval_records = []
        for k in ks:
            if k > total_hosts:
                continue
            top_k = ranked_df.head(k)
            tp = int(top_k["is_threat_host"].sum())
            fp = k - tp
            fn = total_threat_hosts - tp
            tn = total_hosts - k - fn

            recall = tp / total_threat_hosts if total_threat_hosts > 0 else 0.0
            precision = tp / k
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

            eval_records.append({
                "Top_K": k,
                "Workforce_Pct": f"{round((k / total_hosts) * 100, 2)}%",
                "True_Positives": tp,
                "False_Positives": fp,
                "Recall": f"{round(recall * 100, 2)}%",
                "Precision": f"{round(precision * 100, 2)}%",
                "F1_Score": round(f1, 4)
            })

        return pd.DataFrame(eval_records)
