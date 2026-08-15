# Isolation Forest Domain Anomaly Models — Technical Documentation

## 1. Model Overview

The **Isolation Forest** stage forms **Level 1** of the InsiEDR defense-in-depth architecture. It operates as an unsupervised anomaly detection engine that models normal employee baseline behaviors across four discrete organizational domains:
1. **Logon Domain** (Authentication & PC access)
2. **File Domain** (File read, write, copy activities)
3. **Device/USB Domain** (Removable media connections)
4. **HTTP Domain** (Web browsing & external network requests)

Instead of training a single monolithic model over all features, InsiEDR trains **four independent Isolation Forest models** (`DomainIsolationForest`), allowing domain-specific anomaly signals to be isolated and evaluated without cross-domain feature interference.

```
                  ┌────────────────────────────────────────┐
                  │   Raw Extracted Features (31 cols)     │
                  └───────────────────┬────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┬──────────────────────────┐
           │ (10 features)            │ (4 features)             │ (6 features)             │ (11 features)
           ▼                          ▼                          ▼                          ▼
 ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
 │  Logon Isolation  │      │  File Isolation   │      │  Device Isolation │      │  HTTP Isolation   │
 │      Forest       │      │      Forest       │      │      Forest       │      │      Forest       │
 └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
           │                          │                          │                          │
           ▼                          ▼                          ▼                          ▼
      `logon_risk`               `file_risk`               `device_risk`              `http_risk`
           │                          │                          │                          │
           └──────────────────────────┴────────────┬─────────────┴──────────────────────────┘
                                                   │
                                                   ▼
                                     ┌───────────────────────────┐
                                     │  SHAP-Weighted Fusion     │
                                     │     -> overall_risk       │
                                     └───────────────────────────┘
```

---

## 2. Input Data & Feature Breakdown

The input data fed to the Isolation Forest stage consists of **31 statistical features** computed per user per calendar day (derived from the raw logs in `INPUT_LOGS/`).

### 2.1 Logon Domain Features (10 Features)
Fed into: `DomainIsolationForest.logon_model`

| Feature Name | Data Type | Description |
|---|---|---|
| `logon_count` | Integer | Total count of logon events recorded for the user on that day. |
| `logoff_count` | Integer | Total count of logoff events recorded for the user on that day. |
| `unique_pc_count` | Integer | Cumulative count of distinct computer workstations accessed by the user up to this date. |
| `daily_unique_pc_count` | Integer | Number of distinct computer workstations accessed on this specific day. |
| `after_hours_logon` | Integer | Number of logon events occurring outside normal working hours (before 07:00 or after 18:00). |
| `daily_after_hours_logon_ratio` | Float | Fraction of total logons that occurred outside business hours (`after_hours_logon / logon_count`). |
| `first_logon_time` | Float | Hour of the earliest logon event of the day (0.0 to 23.0). |
| `last_logoff_time` | Float | Hour of the latest logoff event of the day (0.0 to 23.0). |
| `weekend_logon` | Binary (0/1) | Flag indicating whether any authentication activity occurred on Saturday or Sunday. |
| `daily_pc_access_entropy` | Float | Shannon entropy measuring workstation diversity accessed during the day: $H = -\sum p_i \log_2 p_i$. |

### 2.2 File Domain Features (4 Features)
Fed into: `DomainIsolationForest.file_model`

| Feature Name | Data Type | Description |
|---|---|---|
| `file_access_count` | Integer | Total count of file system operations (read, copy, delete, modify) performed that day. |
| `daily_unique_filename_count` | Integer | Number of distinct filenames interacted with on that day. |
| `daily_new_filename_count` | Integer | Number of filenames accessed that have never been seen in prior days for this user. |
| `daily_file_access_entropy` | Float | Shannon entropy measuring the dispersion of accesses across different file extensions and paths. |

### 2.3 Device / USB Domain Features (6 Features)
Fed into: `DomainIsolationForest.device_model`

| Feature Name | Data Type | Description |
|---|---|---|
| `usb_connect_count` | Integer | Total number of USB/removable mass storage insertion events. |
| `usb_disconnect_count` | Integer | Total number of USB/removable media removal events. |
| `after_hours_usb_usage` | Integer | Number of USB connections initiated outside regular working hours. |
| `daily_device_connect_count` | Integer | Count of distinct external hardware devices connected during the day. |
| `daily_device_usage_flag` | Binary (0/1) | Active flag indicating if any removable media interaction occurred on that day. |
| `first_usb_usage_time` | Float | Timestamp hour (0.0 to 23.0) of the first USB connection (0.0 if none). |

### 2.4 HTTP Domain Features (11 Features)
Fed into: `DomainIsolationForest.http_model`

| Feature Name | Data Type | Description |
|---|---|---|
| `http_count` | Integer | Total HTTP requests recorded for the user on that day. |
| `daily_http_request_count` | Integer | Volume of web browsing transactions processed. |
| `unique_url_count` | Integer | Count of distinct full URLs requested. |
| `suspicious_url_count` | Integer | Count of visits to flagged domains (e.g., `wikileaks.org`, `mediafire.com`). |
| `file_sharing_site_visits` | Integer | Requests sent to cloud storage/file lockers (`dropbox.com`, `box.com`, `mediafire.com`). |
| `job_search_site_visits` | Integer | Requests sent to employment portals (`monster.com`, `indeed.com`, `dice.com`). |
| `http_after_hours` | Integer | HTTP transactions recorded outside business hours. |
| `daily_unique_domain_count` | Integer | Count of distinct top-level and second-level web domains contacted. |
| `daily_new_domain_count` | Integer | Web domains contacted that were never previously visited by this user. |
| `daily_domain_access_entropy` | Float | Shannon entropy measuring the distribution of web requests across destinations. |
| `daily_external_domain_ratio` | Float | Proportion of non-corporate/external web destinations contacted. |

---

## 3. How the Model Works

### 3.1 Algorithm Mechanics
The Isolation Forest algorithm isolates anomalous data points rather than profiling normal points:
1. **Recursive Partitioning**: An isolation tree recursively splits feature dimensions at random split values between the minimum and maximum values of the selected feature.
2. **Path Length**: Anomalous points have unusual attribute combinations and therefore require **fewer random splits** to be isolated into terminal leaf nodes. Normal, dense points require deeper trees.
3. **Anomaly Score Formula**:
   $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
   Where $E(h(x))$ is the average path length of sample $x$ across all $200$ trees, and $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree (BST) for dataset size $n$:
   $$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$

### 3.2 InsiEDR Anomaly Inversion
In standard `scikit-learn`, `score_samples(X)` returns negative values where lower numbers mean more anomalous. InsiEDR explicitly **inverts and negates** the output so higher values represent higher risk:
```python
def score(self, X):
    # Higher value = more anomalous / higher threat potential
    return -self.model.score_samples(X)
```

### 3.3 Model Hyperparameters

| Hyperparameter | Value | Rationale |
|---|---|---|
| `n_estimators` | `200` | High ensemble depth ensures statistical stability of average tree path lengths across large user populations. |
| `contamination` | `0.05` | Assumes that approximately 5% of daily activity within an enterprise could be anomalous baseline noise. |
| `random_state` | `42` | Guarantees deterministic, reproducible tree splits. |
| `n_jobs` | `-1` | Parallelizes tree construction across all available CPU cores for maximum throughput. |

---

## 4. Output of the Isolation Forest Stage

The Isolation Forest stage produces **4 domain risk scores** and **5 aggregated/trend meta-features** that enrich the dataset:

| Output Column | Range | Description |
|---|---|---|
| `logon_risk` | $[0.0, 1.0+]$ | Continuous anomaly score from the Logon Isolation Forest. |
| `file_risk` | $[0.0, 1.0+]$ | Continuous anomaly score from the File Isolation Forest. |
| `device_risk` | $[0.0, 1.0+]$ | Continuous anomaly score from the Device Isolation Forest. |
| `http_risk` | $[0.0, 1.0+]$ | Continuous anomaly score from the HTTP Isolation Forest. |
| `raw_overall_risk` | $[0.0, 1.0]$ | SHAP-weighted sum of domain risks: $\sum_{i=1}^4 w_i \cdot \text{risk}_i$. |
| `overall_risk` | $[0.0, 1.0]$ | Calibrated risk normalized against the maximum observed training risk: $\min(\text{raw\_overall\_risk} / \text{max\_train}, 1.0)$. |
| `daily_risk_delta` | $[-\infty, +\infty]$ | Day-to-day derivative of `overall_risk`: $\text{overall\_risk}_t - \text{overall\_risk}_{t-1}$. |
| `daily_risk_rolling_mean_7d` | $[0.0, 1.0]$ | 7-day backward rolling average of `overall_risk`. |
| `daily_risk_rolling_std_7d` | $[0.0, 1.0]$ | 7-day backward rolling standard deviation measuring volatility in user behavior. |

### Generated Artifacts
- **Model File**: `final_model/output/domain_isolation_forest.pkl` (contains all 4 fitted IF estimators)
- **Enriched Dataset**: `final_model/latest_data/if_enriched_features.csv` (contains raw features + 4 domain risks + rolling trends)
- **Confusion Matrices**: `final_model/confusion_matrices/isolation_forest/` (`logon_if_confusion_matrix.csv`, `file_if_confusion_matrix.csv`, `device_if_confusion_matrix.csv`, `http_if_confusion_matrix.csv`, `overall_if_confusion_matrix.csv`)
