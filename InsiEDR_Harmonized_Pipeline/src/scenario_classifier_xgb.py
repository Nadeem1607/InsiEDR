"""
Tier 2: Multi-Class XGBoost Scenario Classifier Module
Trained on Days 1 to 4 tactical primitives.
Maps non-contiguous scenario classes to contiguous index range [0, num_classes-1].
Gracefully handles single-class feeds (e.g. pure benign training feeds).
"""

import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

class ScenarioXGBClassifier:
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.model = None
        self.encoder = LabelEncoder()
        self.num_classes = 0
        self.fitted = False

    def fit(self, X_train, y_train):
        unique_classes = np.unique(y_train)
        self.num_classes = len(unique_classes)

        if self.num_classes < 2:
            # Single class (e.g., pure benign in training)
            self.model = None
            self.fitted = True
            return self

        y_encoded = self.encoder.fit_transform(y_train)

        if self.num_classes > 2:
            self.model = XGBClassifier(
                objective="multi:softprob",
                num_class=self.num_classes,
                n_estimators=100,
                max_depth=5,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=self.random_state,
                n_jobs=-1,
                eval_metric="mlogloss"
            )
        else:
            self.model = XGBClassifier(
                objective="binary:logistic",
                n_estimators=100,
                max_depth=5,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=self.random_state,
                n_jobs=-1,
                eval_metric="logloss"
            )

        self.model.fit(X_train, y_encoded)
        self.fitted = True
        return self

    def predict(self, X):
        if not self.fitted:
            raise ValueError("Model must be fitted before predict.")
        if self.model is None:
            return np.zeros(len(X), dtype=int)
        preds_encoded = self.model.predict(X)
        return self.encoder.inverse_transform(preds_encoded)

    def predict_proba(self, X):
        if not self.fitted:
            raise ValueError("Model must be fitted before predict_proba.")
        if self.model is None:
            return np.ones((len(X), 1))
        return self.model.predict_proba(X)

    def get_max_threat_prob(self, X):
        """
        Returns max probability across all malicious scenario classes (excluding class 0 / BENIGN).
        """
        if not self.fitted:
            raise ValueError("Model must be fitted before get_max_threat_prob.")
        if self.model is None or self.num_classes < 2:
            return np.zeros(len(X))

        probs = self.predict_proba(X)
        
        # Identify benign column index
        benign_indices = np.where(self.encoder.classes_ == 0)[0]
        benign_idx = benign_indices[0] if len(benign_indices) > 0 else None

        if self.num_classes > 2:
            if benign_idx is not None:
                threat_cols = [i for i in range(self.num_classes) if i != benign_idx]
                return np.max(probs[:, threat_cols], axis=1)
            else:
                return np.max(probs, axis=1)
        elif self.num_classes == 2:
            if benign_idx == 0:
                return probs[:, 1]
            else:
                return probs[:, 0]
        else:
            return np.zeros(len(X))
