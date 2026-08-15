# InsiEDR Multi-Tier Machine Learning Architecture

This directory contains in-depth mathematical and engineering documentation for each machine learning model in the InsiEDR pipeline.

---

## Model Index

### 1. [Isolation Forest Domain Anomaly Models (`isolation_forest.md`)](./isolation_forest.md)
* **Tier**: Level 1 (Unsupervised Domain Anomaly Filtering)
* **Scope**: 4 Independent Models (`Logon`, `File`, `Device`, `HTTP`)
* **Input**: 31 daily statistical features extracted from raw event logs
* **Core Task**: Unsupervised recursive partitioning to isolate anomalous events without requiring prior attack labels
* **Output**: 4 domain anomaly scores (`logon_risk`, `file_risk`, `device_risk`, `http_risk`) and rolling trend features

---

### 2. [Multiclass XGBoost Scenario Classifier (`xgboost_classifier.md`)](./xgboost_classifier.md)
* **Tier**: Level 2 (Supervised Threat Scenario Classification)
* **Scope**: 6-Class Multiclass Decision Tree Ensemble (500 Trees, Depth 6)
* **Input**: 40 features (31 raw statistical + 4 IF domain risks + 5 SHAP risk/trend meta-features)
* **Core Task**: Identifies threat intent across 6 categories: `normal`, `email_exfil`, `sabotage`, `usb_exfil`, `flight_risk`, and `cloud_exfil`
* **Output**: 6-class calibrated probability distribution vector and the max malicious scenario confidence (`scenario_risk`)

---

### 3. [RedRVFL Behavioral Sequence Drift Neural Network (`redrvfl_neural_network.md`)](./redrvfl_neural_network.md)
* **Tier**: Level 3 (Temporal Behavioral Drift & Insider Ranking)
* **Scope**: 5-Layer Stacked RandomLSTM + Closed-Form Ridge Regression Ensemble
* **Input**: 7-day chronological sliding window sequences of fused threat scores ($\text{rvfl\_risk} = 0.3 \cdot \text{overall\_risk} + 0.7 \cdot \text{scenario\_risk}$)
* **Core Task**: Predicts expected behavior on Day 7 based on Days 1–6 and flags behavioral drift via squared prediction error
* **Output**: User-level holistic threat score ($\text{Score\_v2} = \text{max\_error} \times \text{mean\_error} \times \sqrt{N}$) and the Top-K Review Queue ranking (100% insider recall at Top-10)

---

## Pipeline Execution Summary

```
 Raw Logs ──▶ [Isolation Forest (Level 1)] ──▶ 4 Domain Risks
                                                      │
                                                      ▼
                       [XGBoost Classifier (Level 2)] ──▶ 6 Scenario Probabilities
                                                                   │
                                                                   ▼
                         [RedRVFL Sequence Engine (Level 3)] ──▶ Top-K Insider Ranking
```
