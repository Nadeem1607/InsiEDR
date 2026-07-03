# Quick Start

The inference engine exposes three APIs:

1. **Current Risk Assessment**
2. **Scenario Classification**
3. **Behavioral Risk Assessment**

Each API serves a different purpose and should be used at different stages of the detection workflow.

---

# 1. Current Risk Assessment

## What does it do?

Evaluates whether the user's **current activity** appears unusual compared to expected behavior.

This API is intended for:

* Near real-time monitoring
* Endpoint alerting
* Immediate anomaly detection
* Current risk assessment

The model uses domain-specific Isolation Forests trained on:

* Logon activity
* File activity
* Device activity
* HTTP activity

---

## When should I call it?

Call this API whenever a fresh feature vector is available.

Examples:

* Every 5 minutes
* Every hour
* At the end of the day

Typical flow:

```text
Endpoint
    ↓
Generate Feature Vector
    ↓
predict_current_risk()
    ↓
Receive Current Risk
```

---

## Example Input

```python
payload = {

    "features": {

        "logon_count": 12,

        "logoff_count": 12,

        "file_access_count": 25,

        "usb_connect_count": 1,

        "... remaining features ..."

    }

}
```

---

## Example Call

```python
from src.server.inference import (
    predict_current_risk
)

result = predict_current_risk(
    payload
)
```

---

## Example Response

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

## How should I interpret the result?

```text
HIGH
    Significant anomaly detected

MEDIUM
    Suspicious activity detected

LOW
    Activity appears normal
```

---

# 2. Scenario Classification

## What does it do?

Classifies the user's behavior into one of several insider threat scenarios.

The model uses a supervised XGBoost classifier trained on behavioral features and risk indicators.

Supported classes:

```text
normal

s1

s2

s3
```

---

## When should I call it?

Call this API after current risk features have been computed.

The model expects:

* Raw behavioral features
* Isolation Forest risk scores
* Rolling risk statistics

Typical flow:

```text
Generate Features
        ↓
Compute Current Risk
        ↓
Compute Risk Trends
        ↓
predict_scenario()
        ↓
Receive Scenario Probabilities
```

---

## Example Input

```python
payload = {

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

---

## Example Call

```python
from src.server.inference import (
    predict_scenario
)

result = predict_scenario(
    payload
)
```

---

## Example Response

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

## How should I interpret the result?

```text
normal
    No known insider threat pattern detected

s1
    Behavior resembles Scenario 1

s2
    Behavior resembles Scenario 2

s3
    Behavior resembles Scenario 3
```

The confidence score indicates how strongly the model believes the classification.

---

# 3. Behavioral Risk Assessment

## What does it do?

Evaluates whether the user's behavior is deviating from their historical pattern.

This API is intended for:

* Daily analysis
* Long-term monitoring
* Behavioral drift detection
* Insider threat identification

The model uses a RedRVFL sequence model.

---

## When should I call it?

Call this API once sufficient historical observations are available.

Current model requirements:

```text
7 historical observations

+

1 target observation

=

8 total observations
```

Typical flow:

```text
Collect Daily Risk Signals
        ↓
Store Historical Sequence
        ↓
Build Sequence
        ↓
predict_behavioral_risk()
        ↓
Receive Behavioral Risk
```

---

## What data does it use?

The behavioral model uses:

```text
overall_risk

rf_s1_prob

rf_s2_prob

rf_s3_prob
```

These values are combined internally into a single behavioral signal used by the RedRVFL model.

---

## Example Input

```python
payload = {

    "payload_id": "123",

    "username": "RKD0604",

    "hostname": "PC001",

    "daily_sequence": [

        {
            "overall_risk": 0.42,

            "rf_s1_prob": 0.02,

            "rf_s2_prob": 0.01,

            "rf_s3_prob": 0.88
        },

        ...

    ]

}
```

---

## Example Call

```python
from src.server.inference import (
    predict_behavioral_risk
)

result = predict_behavioral_risk(
    payload
)
```

---

## Example Response

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

  "recommended_action":
      "Escalate for analyst review."
}
```

---

## How should I interpret the result?

```text
HIGH
    Strong behavioral deviation

MEDIUM
    Noticeable behavioral change

LOW
    Behavior remains consistent with historical patterns
```

Unlike Current Risk Assessment, this model focuses on long-term behavioral evolution rather than individual anomalous events.

---

# Recommended Usage

The three APIs are designed to work together.

```text
Current Activity
        ↓
predict_current_risk()

Current Threat Pattern
        ↓
predict_scenario()

Historical Behavior
        ↓
predict_behavioral_risk()
```

---

## Example 1

```text
Current Risk: HIGH

Scenario: normal

Behavioral Risk: LOW
```

Interpretation:

```text
Something unusual happened today,
but it does not resemble a known insider scenario
and long-term behavior remains stable.
```

---

## Example 2

```text
Current Risk: MEDIUM

Scenario: s1

Behavioral Risk: HIGH
```

Interpretation:

```text
Current activity resembles a known insider scenario
and the user's behavior has been drifting
significantly over time.

This combination should receive
higher analyst attention.
```

---

## Example 3

```text
Current Risk: LOW

Scenario: normal

Behavioral Risk: LOW
```

Interpretation:

```text
No significant anomaly detected.

Behavior remains consistent with
historical patterns.
```

---

Each API provides a different perspective:

```text
Current Risk
    → What is happening right now?

Scenario Classification
    → What known threat pattern does it resemble?

Behavioral Risk
    → Has behavior changed over time?
```

Together, these signals provide a comprehensive view of user activity and insider threat risk.
