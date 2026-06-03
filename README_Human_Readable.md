# Quick Start

The inference engine exposes two independent APIs:

1. **Current Risk Assessment**
2. **Behavioral Risk Assessment**

These APIs answer different questions and should be used for different purposes.

---

# 1. Current Risk Assessment

## What does it do?

Evaluates whether the user's **current activity** looks unusual.

This API is intended for:

* Near real-time monitoring
* Endpoint alerting
* Immediate anomaly detection

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
Receive Risk Score
```

---

## Example Input

```python
payload = {

    "features": {

        "logon_count": 12,

        "logoff_count": 12,

        "file_copy_count": 5,

        "usb_insert_count": 1,

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
    Suspicious activity

LOW
    Activity appears normal
```

---

# 2. Behavioral Risk Assessment

## What does it do?

Evaluates whether the user's behavior is deviating from their historical pattern.

This API is intended for:

* Daily analysis
* Insider threat detection
* Long-term behavior monitoring

The model uses a RedRVFL sequence model.

---

## When should I call it?

Call this API once enough historical data has been collected.

Current model requirements:

```text
15 days history
+
1 target day
=
16 days minimum
```

Typical flow:

```text
Collect Daily Features
        ↓
Store Daily History
        ↓
Build Sequence
        ↓
predict_behavioral_risk()
        ↓
Receive Behavioral Risk
```

---

## Example Input

```python
payload = {

    "payload_id": "123",

    "username": "RKD0604",

    "hostname": "PC001",

    "daily_sequence": [

        {
            "date": "2026-01-01",

            "features": {
                "... feature values ..."
            }
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

  "rvfl_error": 0.034,

  "behavioral_risk": "MEDIUM",

  "predicted_scenario": {

      "scenario": "unknown",

      "confidence": 0.0

  },

  "recommended_action":
      "Monitor user behavior closely."
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
    Behavior consistent with history
```

---

# Recommended Usage

The two APIs should be used together.

```text
Current Activity
        ↓
predict_current_risk()

Historical Behavior
        ↓
predict_behavioral_risk()
```

Example:

```text
Current Risk: HIGH
Behavioral Risk: LOW
```

Interpretation:

```text
Something unusual happened today,
but the user's long-term behavior
remains consistent.
```

Example:

```text
Current Risk: LOW
Behavioral Risk: HIGH
```

Interpretation:

```text
No major anomaly right now,
but the user's behavior has been
drifting significantly over time.
```

These two signals provide different perspectives and should be evaluated independently.

```
```
