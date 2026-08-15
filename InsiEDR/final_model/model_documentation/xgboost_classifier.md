# XGBoost Scenario Classifier

## 1. Model Overview
The XGBoost Classifier is Level 2 of the InsiEDR pipeline. It performs two distinct jobs:

1. **SHAP Domain Weighting** — Before training, the XGBoost model is used to determine how much each activity domain (Logon, File, Device, HTTP) contributes to insider threat detection. These importance scores are derived using SHAP (SHapley Additive exPlanations) and are used to combine the four Isolation Forest risk scores into a single weighted overall risk score.

2. **Threat Scenario Classification** — After computing the weighted risk score, the XGBoost model classifies each user-day into one of 6 specific insider threat scenarios, giving analysts a clear picture of what kind of attack or exfiltration behavior is taking place.

---

## 2. SHAP Domain Weighting

### What is SHAP?
SHAP is a method for explaining which features (inputs) contribute most to a model's predictions. In this pipeline, XGBoost is trained on all four domain risk scores. SHAP is then applied to that trained model to measure the average contribution of each domain to the final insider threat prediction.

### How the Weights Are Derived:
- The XGBoost model is trained on labeled data containing Logon, File, Device, and HTTP risk scores.
- SHAP values are computed for each domain feature across all training samples.
- The average absolute SHAP value for each domain is used as its importance weight.
- The 4 weights are then normalized so they sum to 1.0.

### Derived Domain Weights:
| Domain | Weight |
|--------|--------|
| HTTP Risk | 61.45% |
| Logon Risk | 18.69% |
| File Risk | 17.37% |
| Device Risk | 2.50% |

This tells us that web browsing behavior (HTTP) is by far the strongest signal for insider threats, while USB/device activity has the smallest individual contribution.

### How the Weights Are Applied:
The four Isolation Forest domain scores are combined using these weights to compute a single `overall_risk` score for each user per day:
- `raw_overall_risk = (0.1737 × file_risk) + (0.0250 × device_risk) + (0.6145 × http_risk) + (0.1869 × logon_risk)`
- The raw score is then normalized relative to the highest score observed during training to produce `overall_risk` (a value between 0.0 and 1.0).

---

## 3. Input Data Fed into the Model

The model receives **40 features per user per day**, combining raw activity statistics with risk scores computed by the Isolation Forest:

### Risk Scores from Level 1 (5 features):
- `overall_risk`: Normalized combined anomaly score.
- `logon_risk`: Anomaly score from login behavior.
- `file_risk`: Anomaly score from file access behavior.
- `device_risk`: Anomaly score from USB/device usage.
- `http_risk`: Anomaly score from web browsing behavior.

### Risk Trend Features (3 features):
- `daily_risk_delta`: Day-on-day change in overall risk.
- `daily_risk_rolling_mean_7d`: 7-day average risk.
- `daily_risk_rolling_std_7d`: 7-day variability of risk.

### Logon Behavior (6 features):
- Login count, logoff count, after-hours logins, weekend logins, first login hour, last logout hour.

### File Behavior (4 features):
- File access count, unique filenames, new filenames, file access entropy.

### Device Behavior (5 features):
- USB connection count, disconnect count, after-hours USB use, distinct devices connected, first USB hour.

### HTTP Behavior (11 features):
- Web request count, unique URLs, suspicious URLs, file-sharing site visits, job-search site visits, after-hours web requests, unique domains, new domains, domain entropy, external domain ratio.

### Target Class (Label):
- `scenario`: One of 6 possible categories — `normal`, `email_exfil`, `sabotage`, `usb_exfil`, `flight_risk`, `cloud_exfil`.

---

## 4. How the Model Works

1. **Class Balancing**: Insider threat cases are rare compared to normal activity. The model applies oversampling on minority classes so every scenario gets equal representation during training.
2. **Gradient Boosted Trees**: XGBoost builds 500 decision trees in sequence. Each new tree corrects the errors made by the previous ones.
3. **Multiclass Classification**: The model computes a probability for each of the 6 threat scenarios simultaneously.
4. **Calibration**: Raw probabilities are calibrated to be well-scaled and reliable for ranking.
5. **Prediction**: For each user-day, the model outputs the most likely scenario and its confidence probability.

---

## 5. Output of the Model

For every user on each day, the model outputs:

- `predicted_scenario`: The single most likely threat category (e.g., `usb_exfil`, `flight_risk`).
- `scenario_risk`: Confidence probability of the predicted scenario (0.0 to 1.0). Higher means more certain.
- **Per-scenario probabilities**: A confidence score for each of the 6 scenarios individually:
  - `prob_normal`
  - `prob_email_exfil`
  - `prob_sabotage`
  - `prob_usb_exfil`
  - `prob_flight_risk`
  - `prob_cloud_exfil`

These outputs allow the pipeline to understand not just *that* a user is suspicious, but *what kind* of insider threat they represent.
