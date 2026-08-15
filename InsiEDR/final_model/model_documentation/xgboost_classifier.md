# XGBoost Multiclass Scenario Classifier — Technical Documentation

## 1. Model Overview

The **Multiclass XGBoost Scenario Classifier** represents **Level 2** of the InsiEDR pipeline. While the Isolation Forest (Level 1) identifies *anomalous* behavior, XGBoost determines the specific **intent and threat category** of that anomaly.

Instead of outputting a simple binary decision (insider vs. normal), the XGBoost model outputs a **calibrated probability distribution across 6 threat scenarios**. This granular classification allows Security Operations Center (SOC) analysts to immediately understand what kind of exfiltration or attack is taking place.

```
       ┌─────────────────────────────────────────────────────────────┐
       │   Input: 40 Features per User-Day                           │
       │   (31 Raw Stats + 4 Domain Risks + 5 SHAP Risk/Trend Meta)  │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │   XGBoost Multiclass Classifier                             │
       │   (500 Trees, Depth 6, Softmax Objective: multi:softprob)   │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │   Output: 6-Class Probability Distribution Vector           │
       │   [P(normal), P(email), P(sabotage), P(usb),                │
       │    P(flight), P(cloud)]                                     │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │   scenario_risk = max(P_email, P_sabotage, P_usb,           │
       │                       P_flight, P_cloud)                    │
       │   (Fed forward into Level 3 RedRVFL Behavioral Drift Engine)│
       └─────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Scenarios & Ground Truth Classes

The model classifies every daily user record into one of 6 mutually exclusive scenario classes:

| Class ID | Target Label | Description | Characteristic Behavioral Indicators |
|---|---|---|---|
| `0` | `normal` | Legitimate business activity | Normal logon patterns, low entropy across domains, zero suspicious destination accesses. |
| `1` | `email_exfil` | Data exfiltration via email | Spike in external emails, unusual attachments, logon during off-hours, sending confidential data to personal addresses. |
| `2` | `sabotage` | System sabotage / intellectual property destruction | Mass file deletions, modifying restricted directory permissions, accessing administrator PCs without authorization. |
| `3` | `usb_exfil` | Data exfiltration via physical USB / mass storage | Heavy file accesses coupled with multiple USB connections, large volume data transfers to removable drives. |
| `4` | `flight_risk` | Employee preparing for resignation / disgruntlement | Repeated browsing to job search engines (`monster.com`, `indeed.com`), subtle data hoarding of personal work portfolios. |
| `5` | `cloud_exfil` | Data exfiltration via unauthorized cloud storage | High external web bandwidth, frequent file uploads to cloud lockers (`dropbox.com`, `mediafire.com`, `box.com`). |

---

## 3. Input Data (40 Total Features)

The XGBoost model ingests a comprehensive **40-feature vector** per user per day. These features are strictly defined in `latest_data/models/scenario_xgb_features.json`:

### 3.1 Raw Behavioral Features (31 Features)
- **Logon Activity (10)**: `logon_count`, `logoff_count`, `unique_pc_count`, `daily_unique_pc_count`, `after_hours_logon`, `daily_after_hours_logon_ratio`, `first_logon_time`, `last_logoff_time`, `weekend_logon`, `daily_pc_access_entropy`
- **File System Activity (4)**: `file_access_count`, `daily_unique_filename_count`, `daily_new_filename_count`, `daily_file_access_entropy`
- **Removable Media Activity (6)**: `usb_connect_count`, `usb_disconnect_count`, `after_hours_usb_usage`, `daily_device_connect_count`, `daily_device_usage_flag`, `first_usb_usage_time`
- **Network / Web Activity (11)**: `http_count`, `daily_http_request_count`, `unique_url_count`, `suspicious_url_count`, `file_sharing_site_visits`, `job_search_site_visits`, `http_after_hours`, `daily_unique_domain_count`, `daily_new_domain_count`, `daily_domain_access_entropy`, `daily_external_domain_ratio`

### 3.2 Domain Anomaly Scores from Level 1 Isolation Forest (4 Features)
- `logon_risk`: Unsupervised authentication anomaly intensity.
- `file_risk`: Unsupervised file system access anomaly intensity.
- `device_risk`: Unsupervised USB connection anomaly intensity.
- `http_risk`: Unsupervised web navigation anomaly intensity.

### 3.3 Fused Risk & Temporal Trend Meta-Features (5 Features)
- `raw_overall_risk`: Direct SHAP-weighted combination of domain risks.
- `overall_risk`: Calibrated, normalized threat score ($0.0$ to $1.0$).
- `daily_risk_delta`: First-order day-over-day derivative of overall risk.
- `daily_risk_rolling_mean_7d`: 7-day backward moving average of risk.
- `daily_risk_rolling_std_7d`: 7-day backward moving standard deviation (captures sudden volatility).

---

## 4. Training Mechanics & Architecture

### 4.1 Stratified User-Level Data Splitting
To evaluate realistic enterprise generalization without data leakage:
- The population (1,000 users) is split **80% Train (800 users)** and **20% Test (200 users)**.
- Splitting is performed **strictly by user ID** rather than by individual record rows. This guarantees that no historical days for a test user ever leak into the training partition.
- The split is stratified across the user's `threat_scenario` to ensure balanced scenario representation in both train and test splits.

### 4.2 Class Imbalance Handling: Balanced Random Oversampling
In production insider threat datasets, normal records vastly outnumber malicious days ($~55,000+$ normal records vs. $~150$ records per insider scenario).

To prevent gradient dominance by class `0` (normal), InsiEDR applies **balanced random oversampling with replacement** on the training partition:
```python
train_dist = y_train_xgb.value_counts().sort_index()
class_0_count = int(train_dist[0])  # ~50,000+ samples

oversampled_X, oversampled_y = [], []
for c in range(6):
    c_X = X_train_xgb[y_train_xgb == c]
    c_y = y_train_xgb[y_train_xgb == c]
    if len(c_X) > 0:
        c_X_samp = c_X.sample(n=class_0_count, replace=True, random_state=42)
        c_y_samp = c_y.sample(n=class_0_count, replace=True, random_state=42)
        oversampled_X.append(c_X_samp)
        oversampled_y.append(c_y_samp)
```
This balances all 6 classes equally during gradient boosting iterations.

### 4.3 XGBoost Hyperparameters

| Hyperparameter | Value | Technical Description |
|---|---|---|
| `objective` | `multi:softprob` | Optimizes multiclass log loss and outputs a normalized probability distribution across all 6 classes. |
| `num_class` | `6` | Total distinct threat scenario classes. |
| `n_estimators` | `500` | Number of sequential gradient boosted decision trees. |
| `max_depth` | `6` | Controls model capacity and enables learning of complex higher-order feature interactions between raw counts and IF risks. |
| `learning_rate` | `0.05` | Step size shrinkage used to prevent overfitting on oversampled minority classes. |
| `subsample` | `0.80` | Randomly samples 80% of training instances prior to growing each tree (adds stochastic regularization). |
| `colsample_bytree` | `0.80` | Randomly samples 80% of features at each split to decorrelate individual trees. |
| `eval_metric` | `mlogloss` | Multiclass log loss used for convergence monitoring. |
| `random_state` | `42` | Guarantees deterministic, reproducible gradient splits. |
| `n_jobs` | `-1` | Multi-threaded execution utilizing all available CPU cores. |

---

## 5. Output of the XGBoost Stage

For every user-day record, the model outputs **6 scenario probability features**:

| Output Column | Description | Role in Pipeline |
|---|---|---|
| `rf_normal_prob` | $P(\text{Class} = \text{normal})$ | Baseline non-threat probability. |
| `rf_email_exfil_prob` | $P(\text{Class} = \text{email\_exfil})$ | Specific risk probability for email exfiltration. |
| `rf_sabotage_prob` | $P(\text{Class} = \text{sabotage})$ | Specific risk probability for system/data sabotage. |
| `rf_usb_exfil_prob` | $P(\text{Class} = \text{usb\_exfil})$ | Specific risk probability for USB data exfiltration. |
| `rf_flight_risk_prob` | $P(\text{Class} = \text{flight\_risk})$ | Specific risk probability for employee departure risk. |
| `rf_cloud_exfil_prob` | $P(\text{Class} = \text{cloud\_exfil})$ | Specific risk probability for cloud data upload exfiltration. |

### Downstream Signal Construction (`scenario_risk`):
The maximum probability among all malicious classes is extracted to represent the day's active threat magnitude:
$$\text{scenario\_risk} = \max\Big(P_{\text{email}}, P_{\text{sabotage}}, P_{\text{usb}}, P_{\text{flight}}, P_{\text{cloud}}\Big)$$

This signal is directly fused with `overall_risk` and fed into **Level 3 RedRVFL**:
$$\text{rvfl\_risk} = 0.3 \cdot \text{overall\_risk} + 0.7 \cdot \text{scenario\_risk}$$

### Generated Artifacts
- **Model File**: `final_model/output/xgb_model.pkl`
- **Dataset with Probabilities**: `final_model/output/scenario_training_dataset_with_xgb_shap.csv`
- **6x6 Multiclass Confusion Matrix**: `final_model/confusion_matrices/xgboost/xgboost_multiclass_confusion_matrix.csv`
- **Binary Confusion Matrix**: `final_model/confusion_matrices/xgboost/xgboost_binary_confusion_matrix.csv`
- **Classification Report**: `final_model/confusion_matrices/xgboost/xgboost_classification_report.txt`
