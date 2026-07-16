from __future__ import annotations

import sys
import os
import json
import pickle
from typing import Any, Dict

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from server.detectors.base import Detector
from server.config import config


class RandomForestDetector(Detector):
    """Supervised Random Forest for Insider Threat scenario detection."""
    
    @property
    def name(self) -> str:
        return "random_forest_scenario"

    def __init__(self):
        super().__init__()
        if config.model_inference_dir:
            base_model_dir = os.path.join(config.model_inference_dir, config.active_model_version)
        else:
            base_model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.data', 'models', config.active_model_version))
            
        self.model_path = os.path.join(base_model_dir, "rf_model.pkl")
        self.features_path = os.path.join(base_model_dir, "rf_features.json")
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
                print(f"Error loading RF model: {e}")

    def train_model(self, storage: Any, days: int = 30) -> Dict[str, Any]:
        """Pulls historical data, labels critical agents as 1, trains and saves the model."""
        print(f"Fetching last {days} days of normalized features and ground-truth labels for training...")
        with storage.connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT nf.payload_id, nf.agent_id, nf.feature_name, nf.feature_value_numeric,
                           COALESCE(tl.is_malicious, false) as label
                    FROM normalized_features nf
                    LEFT JOIN training_labels tl ON nf.agent_id = tl.agent_id
                    WHERE nf.created_at >= CURRENT_TIMESTAMP - INTERVAL '%s days'
                      AND nf.feature_value_numeric IS NOT NULL
                    """,
                    (days,)
                )
                rows = cursor.fetchall()
        
        if not rows:
            return {"status": "error", "message": "No numerical feature data found for training."}

        df_raw = pd.DataFrame(rows, columns=['payload_id', 'agent_id', 'feature_name', 'feature_value', 'label'])
        
        # Pivot the features so each payload is one row
        print("Pivoting feature data into a training matrix...")
        df_pivot = df_raw.pivot_table(
            index=['payload_id', 'agent_id', 'label'], 
            columns='feature_name', 
            values='feature_value', 
            aggfunc='first'
        ).reset_index()

        # Fill missing values with 0
        df_pivot.fillna(0, inplace=True)

        feature_columns = [c for c in df_pivot.columns if c not in ('payload_id', 'agent_id', 'label')]
        
        if not feature_columns:
            return {"status": "error", "message": "No valid feature columns extracted."}

        X = df_pivot[feature_columns]
        y = df_pivot['label']
        
        print(f"Training RandomForestClassifier on {len(X)} samples with {len(feature_columns)} features...")
        clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=1)
        clf.fit(X, y)
        
        # Save model and features
        with open(self.model_path, 'wb') as f:
            pickle.dump(clf, f)
        with open(self.features_path, 'w') as f:
            json.dump(feature_columns, f)

        # Reload into memory
        self.model = clf
        self.feature_cols = feature_columns
        
        score = clf.score(X, y)
        print(f"Training Complete! Accuracy: {score:.4f}")
        return {
            "status": "success", 
            "message": "Model trained successfully", 
            "samples": len(X),
            "features": len(feature_columns),
            "accuracy": score
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
        
        # Confidence based on baseline existence
        confidence = min(baseline.sample_count / 14.0, 1.0) if baseline and baseline.sample_count > 0 else 0.5
        result["confidence"] = confidence

        if not self.model or not self.feature_cols:
            result["reason"] = "Model not trained."
            result["confidence"] = 0.0
            return result
            
        try:
            # Construct feature vector based on trained columns
            X_input = [features.get(col, 0.0) for col in self.feature_cols]
            X_input_df = pd.DataFrame([X_input], columns=self.feature_cols)
            
            # Predict
            prob = self.model.predict_proba(X_input_df)[0][1]  # Probability of class 1 (malicious)
            
            result["score"] = float(prob * 100.0)
            
            if prob > 0.6:
                result["is_anomaly"] = True
                result["reason"] = f"Random Forest detected high risk pattern (Prob: {prob:.2f})"
                
                # Approximate feature contributions using feature importances
                importances = self.model.feature_importances_
                top_idx = importances.argsort()[-3:][::-1]
                for idx in top_idx:
                    col = self.feature_cols[idx]
                    result["feature_contributions"][f"rf_{col}_impact"] = importances[idx]
            else:
                result["reason"] = f"No malicious patterns detected (Prob: {prob:.2f})"
                
        except Exception as e:
            result["reason"] = f"Random Forest execution failed: {e}"
            result["confidence"] = 0.0
            
        return result
