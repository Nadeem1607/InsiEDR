"""
Tier 1: Domain Isolation Forest Anomaly Detection Module
Strictly fit on Clean Background Hosts (209 non-target workstations) during Days 1 to 4.
Frozen before inference on Validation (Day 5) and Test (Days 6 to 7).
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

class DomainIsolationForest:
    def __init__(self, contamination=0.03, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
            max_samples="auto",
            n_jobs=-1
        )
        self.fitted = False
        self.min_raw_score = None
        self.max_raw_score = None
        self.const_feature_indices = np.array([], dtype=int)
        self.const_baseline_values = np.array([], dtype=float)

    def fit(self, X_clean):
        """
        Fits on verified clean background records.
        Automatically identifies any zero-variance features (e.g. silent honeypots, zero-counters)
        where standard tree splits degenerate.
        """
        X_arr = np.asarray(X_clean, dtype=float)
        
        # Identify zero-variance baseline features purely from data distribution
        stds = np.nanstd(X_arr, axis=0)
        zero_var_mask = np.isclose(stds, 0.0)
        self.const_feature_indices = np.where(zero_var_mask)[0]
        if len(self.const_feature_indices) > 0:
            self.const_baseline_values = X_arr[0, self.const_feature_indices]
        else:
            self.const_baseline_values = np.array([], dtype=float)

        self.model.fit(X_arr)
        self.fitted = True
        
        # Calibration bounds on training clean split
        raw_scores = -self.model.score_samples(X_arr)
        self.min_raw_score = float(np.percentile(raw_scores, 1))
        self.max_raw_score = float(np.percentile(raw_scores, 99))
        return self

    def score_anomaly(self, X):
        """
        Returns normalized anomaly score between 0.0 and 1.0.
        Higher score = higher anomaly.
        Detects both continuous tree-depth anomalies and baseline support violations.
        """
        if not self.fitted:
            raise ValueError("DomainIsolationForest must be fitted before scoring.")
        
        X_arr = np.asarray(X, dtype=float)
        raw = -self.model.score_samples(X_arr)
        denom = max(self.max_raw_score - self.min_raw_score, 1e-6)
        normalized = np.clip((raw - self.min_raw_score) / denom, 0.0, 1.0)

        # Generic baseline support violation: any feature that was strictly constant
        # during clean training that now deviates in test is an out-of-distribution event.
        if len(self.const_feature_indices) > 0:
            diffs = ~np.isclose(X_arr[:, self.const_feature_indices], self.const_baseline_values)
            has_violation = np.any(diffs, axis=1)
            normalized = np.where(has_violation, 1.0, normalized)

        return normalized

    def predict(self, X):
        """
        Returns binary decision: 1 (Anomaly) vs 0 (Normal).
        """
        scores = self.score_anomaly(X)
        return (scores >= 0.5).astype(int)
