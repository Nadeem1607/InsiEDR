from __future__ import annotations

import os
import json
import pickle
import pandas as pd
from typing import Any, Dict

from sklearn.ensemble import IsolationForest

from server.detectors.base import Detector


class IsolationForestDetector(Detector):
    """Unsupervised Isolation Forest to detect novel zero-day behaviors."""
    
    @property
    def name(self) -> str:
        return "isolation_forest"

    def __init__(self):
        super().__init__()
        base_model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.data', 'models'))
        self.model_path = os.path.join(base_model_dir, "if_model.pkl")
        self.features_path = os.path.join(base_model_dir, "if_features.json")
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        self.model = None
        self.feature_cols = []
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path) and os.path.exists(self.features_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.features_path, 'r') as f:
                    self.feature_cols = json.load(f)
            except Exception as e:
                print(f"Error loading IF model: {e}")

    def train_model(self, storage: Any, days: int = 30) -> Dict[str, Any]:
        """Trains an unsupervised Isolation Forest on recent historical data."""
        print(f"[IsolationForest] Fetching last {days} days of features...")
        with storage.connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT payload_id, agent_id, feature_name, feature_value_numeric 
                    FROM normalized_features
                    WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '%s days'
                      AND feature_value_numeric IS NOT NULL
                    """,
                    (days,)
                )
                rows = cursor.fetchall()
        
        if not rows:
            return {"status": "error", "message": "No numerical feature data found for training IF."}

        df_raw = pd.DataFrame(rows, columns=['payload_id', 'agent_id', 'feature_name', 'feature_value'])
        df_pivot = df_raw.pivot_table(
            index=['payload_id', 'agent_id'], 
            columns='feature_name', 
            values='feature_value', 
            aggfunc='first'
        ).reset_index()

        df_pivot.fillna(0, inplace=True)
        
        feature_columns = [c for c in df_pivot.columns if c not in ('payload_id', 'agent_id')]
        if not feature_columns:
            return {"status": "error", "message": "No valid feature columns extracted for IF."}

        X = df_pivot[feature_columns]
        
        print(f"[IsolationForest] Training on {len(X)} samples with {len(feature_columns)} features...")
        clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=1)
        clf.fit(X)
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(clf, f)
        with open(self.features_path, 'w') as f:
            json.dump(feature_columns, f)

        self.model = clf
        self.feature_cols = feature_columns
        
        return {
            "status": "success", 
            "message": "Isolation Forest trained successfully", 
            "samples": len(X),
            "features": len(feature_columns)
        }

    def detect(self, payload_id: str, agent_id: str, username: str, features: Dict[str, float], baseline: Any) -> Dict[str, Any]:
        result = {
            "detector_name": self.name,
            "score": 0.0,
            "confidence": 0.0,
            "is_anomaly": False,
            "feature_contributions": {},
            "reason": "Normal behavior."
        }
        
        confidence = min(baseline.sample_count / 14.0, 1.0) if baseline and baseline.sample_count > 0 else 0.5
        result["confidence"] = confidence

        if not self.model or not self.feature_cols:
            result["reason"] = "Isolation Forest model not trained."
            result["confidence"] = 0.0
            return result
            
        try:
            X_input = [features.get(col, 0.0) for col in self.feature_cols]
            X_input_df = pd.DataFrame([X_input], columns=self.feature_cols)
            
            # Predict outlier: -1 is outlier, 1 is inlier
            pred = self.model.predict(X_input_df)[0]
            
            # anomaly score: smaller means more anomalous.
            raw_score = self.model.score_samples(X_input_df)[0]
            
            # Scale score loosely. It usually ranges from roughly -0.8 to -0.4.
            # We map lower values (more negative) to higher risk scores (0-100).
            scaled_score = float(max(0.0, min(100.0, (-raw_score - 0.4) * 200)))
            
            result["score"] = scaled_score
            
            if pred == -1 or scaled_score > 60.0:
                result["is_anomaly"] = True
                result["reason"] = f"Isolation Forest detected novel outlier behavior (Score: {scaled_score:.2f})"
            else:
                result["reason"] = f"No novel anomalies detected (Score: {scaled_score:.2f})"
                
        except Exception as e:
            result["reason"] = f"Isolation Forest execution failed: {e}"
            result["confidence"] = 0.0
            
        return result
