# Stateless Inference Engine for Insider Threat Detection

## Overview

This module implements a stateless inference engine for insider threat detection using two independent detection systems:

1. **Domain Isolation Forests** — Detect current behavioral anomalies using domain-specific anomaly detectors.
2. **RedRVFL Behavioral Model** — Detect long-term behavioral deviations using sequence-based prediction.

The system is designed to operate without maintaining server-side state. All historical context required for behavioral analysis is supplied by the caller.

---

# Architecture

The inference engine exposes two independent APIs:

```text
predict_current_risk()
        │
        └── Isolation Forest

predict_behavioral_risk()
        │
        └── RedRVFL

predict_scenario()
        │
        └── Future Extension
```

No risk fusion is performed.

Current behavioral anomalies and long-term behavioral deviations are evaluated independently.

---

# Model Components

## 1. Domain Isolation Forest

The Isolation Forest system evaluates behavior across four domains:

* Logon Activity
* File Activity
* Device Activity
* HTTP Activity

Each domain is scored independently.

The final anomaly score is the average of the four domain scores.

This detector is intended for:

* Near real-time monitoring
* Immediate anomaly detection
* Endpoint risk assessment

---

## 2. RedRVFL Behavioral Model

The RedRVFL model evaluates behavioral drift across time.

It receives a sequence of daily feature vectors and predicts the next day's expected behavior.

Behavioral deviation is calculated as:

```text
Mean Squared Error (MSE)

between

Actual Features
and
Predicted Features
```

Higher error indicates greater deviation from historical behavior.

This detector is intended for:

* Daily risk evaluation
* Long-term behavioral monitoring
* Insider threat detection based on temporal behavior changes

---

# Persisted Model Artifacts

The inference engine requires the following files:

```text
models/

domain_isolation_forest.pkl

feature_scaler.pkl

ridge_models.pkl

rvfl_metadata.json

feature_columns.json
```

These artifacts must exist before the engine can initialize.

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

    "logon_count": 12,
    "logoff_count": 12,

    "... all required features ..."
  }
}
```

### Requirements

The feature dictionary must contain every feature listed in:

```text
models/feature_columns.json
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

  "overall_score": 0.82,

  "risk_level": "HIGH",

  "domain_scores": {

      "logon": 0.91,

      "file": 0.73,

      "device": 0.62,

      "http": 0.88

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

# API 2 — Behavioral Risk Assessment

## Import

```python
from src.server.inference import (
    predict_behavioral_risk
)
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
          "date": "2026-01-01",

          "features": {

              "... all required features ..."

          }
      }

  ]
}
```

---

## Sequence Requirements

The behavioral model requires:

```text
sequence_length + 1
```

daily feature vectors.

Current model configuration:

```text
15 history days

+

1 target day

=

16 total days
```

Minimum required sequence length:

```text
16 days
```

---

## Feature Requirements

Each daily feature vector must contain all features defined in:

```text
models/feature_columns.json
```

Missing features raise:

```python
ValueError
```

Unexpected features generate:

```python
UserWarning
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

  "rvfl_error": 0.034,

  "behavioral_risk": "MEDIUM",

  "predicted_scenario": {

      "scenario": "unknown",

      "confidence": 0.0

  },

  "sequence_length_received": 16,

  "sequence_length_expected": 16,

  "model_versions": {

      "rvfl_model": "v1",

      "scenario_model": "none"

  },

  "recommended_action":
      "Monitor user behavior closely."
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

# Scenario Prediction

The current implementation contains a placeholder scenario prediction interface.

Current response:

```json
{
  "scenario": "unknown",
  "confidence": 0.0
}
```

Future versions will support supervised scenario classification for:

```text
Normal User

Scenario 1

Scenario 2

Scenario 3
```

along with confidence scores.

---

# Stateless Deployment Design

The server maintains no user history.

All behavioral context is supplied by the caller.

Recommended architecture:

```text
Endpoint Agent
    │
    ├── Collect daily features
    │
    ├── Maintain rolling history
    │
    └── Submit daily sequence
            │
            ▼

Stateless Inference Engine
            │
            ├── Current Risk
            │
            ├── Behavioral Risk
            │
            └── Scenario Prediction
```

This design allows horizontal scaling without centralized session storage.

---

# Thread Safety

The inference engine is read-only after initialization.

All models are loaded once during startup.

Inference requests:

* Do not modify model state
* Do not update weights
* Do not persist user information

The engine is suitable for:

* FastAPI
* Flask
* gRPC
* Multi-threaded deployments
* Multi-process deployments

---

# Future Roadmap

Planned extensions include:

* Scenario Classification Models
* Endpoint-side 5-minute Window Analysis
* Streaming Isolation Forest Evaluation
* Top-K Insider Tracking
* Risk Trend Visualization
* Analyst Investigation Reports
* Confidence-Calibrated Scenario Prediction

```
```
