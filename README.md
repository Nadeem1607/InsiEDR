# Stateless Insider Threat Detection Inference Engine

## Overview

This module implements a stateless insider threat detection platform composed of three specialized machine learning models:

1. **Domain Isolation Forests** — Current anomaly detection
2. **XGBoost Scenario Classifier** — Insider scenario classification
3. **RedRVFL Behavioral Model** — Long-term behavioral drift detection

Each model serves a distinct purpose within the detection pipeline.

The system maintains no server-side state. All historical context required for temporal analysis must be supplied by the caller.

---

# Architecture

```text
Raw Daily Features
        │
        ▼
Isolation Forest
        │
        ├── logon_risk
        ├── file_risk
        ├── device_risk
        ├── http_risk
        └── overall_risk
                │
                ▼
        XGBoost Scenario Model
                │
                ├── rf_normal_prob
                ├── rf_s1_prob
                ├── rf_s2_prob
                └── rf_s3_prob
                        │
                        ▼
                RedRVFL
                        │
                        ▼
                Behavioral Risk
```

---

# Model Components

## 1. Domain Isolation Forest

The Isolation Forest system evaluates current behavioral anomalies across four domains:

* Logon Activity
* File Activity
* Device Activity
* HTTP Activity

Each domain is evaluated independently using a dedicated Isolation Forest model.

The final anomaly score is computed as:

```text
overall_risk

=

mean(
    logon_risk,
    file_risk,
    device_risk,
    http_risk
)
```

### Purpose

* Near real-time anomaly detection
* Endpoint risk assessment
* Current behavioral monitoring

---

## 2. XGBoost Scenario Classifier

The XGBoost model performs supervised insider scenario classification.

Supported classes:

```text
normal

s1

s2

s3
```

The classifier produces class probabilities:

```text
rf_normal_prob

rf_s1_prob

rf_s2_prob

rf_s3_prob
```

### Purpose

* Insider scenario classification
* Scenario-specific risk assessment
* Analyst triage support

### Required Inputs

The model expects:

```text
Raw behavioral features

+

logon_risk
file_risk
device_risk
http_risk
overall_risk

+

daily_risk_delta
daily_risk_rolling_mean_7d
daily_risk_rolling_std_7d
```

Historical risk statistics must be supplied by the caller.

The inference service does not maintain historical state.

---

## 3. RedRVFL Behavioral Drift Model

The RedRVFL model evaluates long-term behavioral deviations.

The model operates on a single fused risk signal derived from the outputs of the Isolation Forest and XGBoost models.

Scenario risk is calculated as:

```text
scenario_risk

=

max(
    rf_s1_prob,
    rf_s2_prob,
    rf_s3_prob
)
```

The final behavioral signal is:

```text
rvfl_risk

=

0.3 × overall_risk

+

0.7 × scenario_risk
```

The model predicts the next day's expected risk value.

Behavioral deviation is measured using:

```text
Mean Squared Error (MSE)

between

Actual rvfl_risk

and

Predicted rvfl_risk
```

Higher error indicates stronger behavioral drift.

### Purpose

* Long-term behavioral monitoring
* Behavioral change detection
* Insider threat identification

---

# Persisted Model Artifacts

The inference engine requires the following files:

```text
models/

domain_isolation_forest.pkl

scenario_xgb.pkl

scenario_xgb_features.json

ridge_models.pkl

rvfl_metadata.json

feature_columns_IF.json

feature_columns.json
```

All artifacts must exist before initialization.

---

# API 1 — Current Risk Assessment

## Import

```python
from src.server.inference import (
    predict_current_risk
)
```

---

## Input Format

```json
{
  "features": {

    "... all required IF features ..."

  }
}
```

### Requirements

The feature dictionary must contain all features listed in:

```text
models/feature_columns_IF.json
```

Missing features raise:

```python
ValueError
```

---

## Example

```python
from src.server.inference import (
    predict_current_risk
)

payload = {

    "features": {

        "logon_count": 12,
        "logoff_count": 12

    }

}

result = predict_current_risk(
    payload
)
```

---

## Response Format

```json
{
  "detector": "isolation_forest",

  "overall_score": 0.61,

  "risk_level": "MEDIUM",

  "domain_scores": {

      "logon": 0.72,

      "file": 0.58,

      "device": 0.49,

      "http": 0.67

  }
}
```

---

## Current Risk Thresholds

```text
overall_score >= 0.80
    HIGH

overall_score >= 0.50
    MEDIUM

otherwise
    LOW
```

---

# API 2 — Scenario Classification

## Import

```python
from src.server.inference import (
    predict_scenario
)
```

---

## Input Format

```json
{
  "features": {

      "... raw features ...",

      "logon_risk": 0.71,

      "file_risk": 0.52,

      "device_risk": 0.44,

      "http_risk": 0.61,

      "overall_risk": 0.57,

      "daily_risk_delta": 0.08,

      "daily_risk_rolling_mean_7d": 0.49,

      "daily_risk_rolling_std_7d": 0.12

  }
}
```

### Requirements

The feature dictionary must contain all features listed in:

```text
models/scenario_xgb_features.json
```

Missing features raise:

```python
ValueError
```

---

## Example

```python
from src.server.inference import (
    predict_scenario
)

payload = {

    "features": {
        ...
    }

}

result = predict_scenario(
    payload
)
```

---

## Response Format

```json
{
  "scenario": "s1",

  "confidence": 0.91,

  "rf_normal_prob": 0.03,

  "rf_s1_prob": 0.91,

  "rf_s2_prob": 0.04,

  "rf_s3_prob": 0.02
}
```

---

# API 3 — Behavioral Risk Assessment

## Import

```python
from src.server.inference import (
    predict_behavioral_risk
)
```

---

## Sequence Requirements

Current model configuration:

```text
sequence_length = 7
```

Required sequence:

```text
7 historical observations

+

1 target observation

=

8 total observations
```

---

## Input Format

```json
{
  "payload_id": "123",

  "username": "RKD0604",

  "hostname": "PC001",

  "daily_sequence": [

      {
          "overall_risk": 0.42,

          "rf_s1_prob": 0.02,

          "rf_s2_prob": 0.01,

          "rf_s3_prob": 0.88
      }

  ]
}
```

### Requirements

Each daily record must contain:

```text
overall_risk

rf_s1_prob

rf_s2_prob

rf_s3_prob
```

Missing features raise:

```python
ValueError
```

---

## Example

```python
from src.server.inference import (
    predict_behavioral_risk
)

payload = {

    "payload_id": "123",

    "username": "RKD0604",

    "hostname": "PC001",

    "daily_sequence": [
        ...
    ]

}

result = predict_behavioral_risk(
    payload
)
```

---

## Response Format

```json
{
  "payload_id": "123",

  "username": "RKD0604",

  "hostname": "PC001",

  "rvfl_error": 0.067,

  "behavioral_risk": "HIGH",

  "predicted_scenario": {

      "scenario": "s3",

      "confidence": 0.88

  },

  "sequence_length_received": 8,

  "sequence_length_expected": 7,

  "model_versions": {

      "rvfl_model": "v1",

      "scenario_model": "external"

  },

  "recommended_action":
      "Escalate for analyst review."
}
```

---

## Behavioral Risk Thresholds

```text
rvfl_error >= 0.05
    HIGH

rvfl_error >= 0.02
    MEDIUM

otherwise
    LOW
```

---

# Stateless Deployment Design

The inference engine maintains no user history.

The client system is responsible for:

```text
Daily feature collection

Historical storage

Risk trend computation

Rolling window maintenance

Sequence generation
```

The inference service is responsible for:

```text
Current anomaly scoring

Scenario classification

Behavioral drift detection
```

Recommended deployment architecture:

```text
Endpoint Agent
    │
    ├── Collect daily features
    │
    ├── Maintain historical state
    │
    ├── Compute risk trend features
    │
    └── Submit inference requests
            │
            ▼

Stateless Inference Engine
            │
            ├── Current Risk
            │
            ├── Scenario Classification
            │
            └── Behavioral Risk
```

---

# Thread Safety

The inference engine is read-only after initialization.

All models are loaded once during startup.

Inference requests:

* Do not modify model state
* Do not update model weights
* Do not persist user information

Suitable for:

* FastAPI
* Flask
* gRPC
* Multi-threaded deployments
* Multi-process deployments

---

# Current Production Status

Implemented and validated:

```text
✓ Domain Isolation Forest

✓ XGBoost Scenario Classification

✓ RedRVFL Behavioral Drift Detection

✓ End-to-End Integration

✓ Stateless Deployment
```

---

# Future Roadmap

Planned enhancements:

* Analyst Investigation Reports
* Risk Visualization Dashboards
* Confidence Calibration
* Streaming Evaluation Pipelines
* Top-K Insider Tracking
* Temporal Scenario Analytics
* Explainability Enhancements
* Multi-Tenant Deployment Support
