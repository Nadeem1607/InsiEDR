"""
Tier 3: InsiEDR Temporal Risk Fusion & Workstation Triage Aggregator Module
Fuses:
  fused_risk = 0.3 * (Tier 1 Anomaly Score) + 0.7 * (Tier 2 Scenario Max Probability)
Aggregates sliding risk error and drift per workstation to produce the Top-K Review Queue.
"""

import numpy as np
import pandas as pd

class TemporalRiskAggregator:
    def __init__(self, if_weight=0.3, xgb_weight=0.7):
        self.if_weight = if_weight
        self.xgb_weight = xgb_weight

    def fuse_risk(self, anomaly_scores, scenario_probs):
        """
        Combines Tier 1 anomaly scores and Tier 2 scenario probabilities using adaptive dual-path fusion.
        Ensures novel/zero-day attacks where scenario probability is 0 are not suppressed.
        """
        anom = np.asarray(anomaly_scores, dtype=float)
        scen = np.asarray(scenario_probs, dtype=float)
        weighted = self.if_weight * anom + self.xgb_weight * scen
        return np.maximum(anom, weighted)

    def rank_workstations(self, df_scored):
        """
        Aggregates fused risk per workstation:
          score = max_risk * mean_risk * sqrt(active_anomalous_ticks)
        Returns ranked DataFrame of workstations.
        """
        records = []
        for host, group in df_scored.groupby("hostname"):
            risks = group["fused_risk"].values
            is_threat_host = int(group["is_threat"].max())
            threat_scenario = group["scenario_id"].loc[group["is_threat"] == 1].iloc[0] if is_threat_host else "BENIGN"
            
            # Anomaly events where fused risk exceeds baseline floor
            high_risk_ticks = (risks >= 0.3).sum()
            max_r = float(np.max(risks))
            mean_r = float(np.mean(risks))
            
            # Persistent host triage score
            host_score = max_r * mean_r * np.sqrt(max(high_risk_ticks, 1))
            
            records.append({
                "hostname": host,
                "is_threat_host": is_threat_host,
                "threat_scenario": threat_scenario,
                "total_ticks": len(risks),
                "high_risk_ticks": int(high_risk_ticks),
                "max_risk": round(max_r, 4),
                "mean_risk": round(mean_r, 4),
                "host_score": round(host_score, 4)
            })

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
