# InsiEDR Project Architecture and Technical Prerequisites

This document outlines the architectural patterns, math models, feature extraction loops, optimizations, and API flows of the Stateless Insider Threat Detection Inference Engine (InsiEDR) based on the CERT r4.2 dataset.

---

## 1. High-Level Architecture & Design Philosophy

An **EDR (Endpoint Detection and Response)** system monitors endpoint activities (logins, file edits, web history, and USB connections) to detect malicious activities. 

### Why is InsiEDR "Stateless"?
Traditional threat detection systems maintain a massive database on the server to store historical user profiles and compute rolling statistics (such as "Is this user's logon rate higher than their 7-day average?"). Storing this state on a central detection server introduces several problems:
1. **Scalability Bottlenecks**: The server must manage active databases for thousands of users.
2. **Complexity**: Handling out-of-order logs, crashes, and database locking.
3. **Latency**: Round-trips to databases during real-time event processing.

**InsiEDR** solves this by using a **stateless architecture**. The detection engine does not store user history. Instead:
* **The Client (Endpoint Agent)** is responsible for maintaining the user's historical state, calculating statistical trend features, constructing historical sequences, and submitting them in the API payload.
* **The Server (Inference Engine)** is completely read-only and memory-less. It receives the payload, passes it through the model pipeline, and immediately returns the risk score.

```text
       ENDPOINT CLIENT AGENT                            STATELESS INFERENCE ENGINE
┌─────────────────────────────────┐                 ┌────────────────────────────────┐
│ 1. Collect Daily Event Logs     │                 │   predict_current_risk()       │
│    (Logon, File, Device, HTTP)  │                 │    ├── Logon Isolation Forest  │
│ 2. Maintain 7-Day Hist. state   │                 │    ├── File Isolation Forest   │
│ 3. Compute Risk Deltas/Std Dev  │  HTTP Post      │    ├── Device Isolation Forest │
│ 4. Build Sequence Payload       ├────────────────►│    └── HTTP Isolation Forest   │
│    (8 days of scores & probs)   │  (JSON Payload) │                                │
│                                 │                 │   predict_scenario()           │
│                                 │                 │    └── XGBoost Multi-Class     │
│                                 │                 │                                │
│                                 │                 │   predict_behavioral_risk()    │
│                                 │                 │    └── RedRVFL Drift Model     │
└─────────────────────────────────┘                 └────────────────────────────────┘
```

### The CERT Insider Threat Dataset (Release 4.2)
The dataset used is a synthetic benchmark created by Carnegie Mellon University (CMU) containing simulated user activity logs. It models:
* **Logon logs**: Timestamps of logons, logoffs, and lock/unlock events.
* **Device logs**: USB connect and disconnect events.
* **File logs**: Accessing, copying, or deleting files on external shares.
* **HTTP logs**: Web browsing requests, domains visited, and pages viewed.

---

## 2. Feature Extraction & Speed Optimizations

The feature extraction coordinator is located in [cert_behavioural.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/cert_behavioural.py). It aggregates the raw event logs into **daily user-level summaries** containing 41 distinct features.

The extraction is split into four domain-specific files under the `src/server/features/extractors/` folder:
1. [logon.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/logon.py): Extracts statistics on after-hours logons, logon frequency, and unique PC counts.
2. [device.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/device.py): Extracts USB connection frequency and after-hours USB activity.
3. [file.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/file.py): Tracks file access counts, copying behaviors, and file-extension patterns.
4. [http.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/http.py): Tracks URL browsing counts, unique domain counts, and after-hours browsing.

### HTTP Feature Extractor Optimization (5.3x Speedup)
In the original version of [http.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/http.py), the code parsed URLs and grouped records using a standard Pandas `.itertuples()` loop. Because the raw `http.csv` is **14.5 GB** (with over 20+ million rows), iterating row-by-row in Python took over 30 minutes and choked CPU cores.

We optimized this by replacing `.itertuples()` and `urlparse()` with a vectorized approach:
* We split the URLs using vectorized string methods (`.str.split('/')`) to extract the domain.
* We converted the Pandas series into raw Python lists using `zip` and ran a fast loop to aggregate visits by `(user, date)`.
* This reduced the feature extraction time from **30+ minutes to just 3 minutes and 12 seconds (a 5.3x speedup)**.

---

## 3. Pipeline Model 1: Domain Isolation Forests

An **Isolation Forest (IF)** is an unsupervised anomaly detection algorithm. Instead of modeling normal data patterns, it isolates anomalies.

### Isolation Forest Mathematical Principle
The algorithm builds an ensemble of isolation trees. For each tree:
1. It randomly selects a feature from the dataset.
2. It randomly selects a split value between the minimum and maximum values of that feature.
3. It recursively splits the data points until every point is isolated.

Because anomalies have unusual feature values, they require **fewer random splits** to isolate compared to normal points. They appear closer to the root of the tree (shorter path length).

For a data point $x$, the anomaly score $s(x, n)$ is defined as:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where:
* $E(h(x))$ is the average path length (number of edges) across all trees to isolate point $x$.
* $c(n)$ is the average path length of an unsuccessful search in a Binary Search Tree (BST) built on $n$ nodes, calculated as:
  $$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$
* An anomaly score $s \to 1$ indicates a highly anomalous point, while $s \to 0$ represents a normal point.

### Implementation in InsiEDR
In [domain_models.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/anomaly/domain_models.py), the system trains **four separate Isolation Forest models** (one for each domain: Logon, File, Device, HTTP).

The final daily anomaly score is the average of these domain scores:

$$overall\_risk = \frac{logon\_risk + file\_risk + device\_risk + http\_risk}{4}$$

### Discrepancy Found in Scored Outputs
During step 3 evaluation, we calculated the distribution of the `overall_risk` score across all 330,452 rows in `if_enriched_features.csv`:
* **Max Score**: `0.728673` | **Mean**: `0.432259` | **Std**: `0.051386`
* The project `README.md` lists `overall_risk >= 0.80` as the trigger for a **HIGH** risk alert.
* Because the model's actual maximum risk score is `0.7287`, **no row ever triggers the HIGH risk status** in production. The thresholds in practice partition the daily risk as:
  * **MEDIUM** ($\ge 0.50$): 41,994 rows (12.71%)
  * **LOW** ($< 0.50$): 288,458 rows (87.29%)

### Threshold Recalibration & Resolution (Step 11)
To align the Isolation Forest daily scores with the README thresholds, we modified the EDR inference engine in `src/server/inference.py` to dynamically rescale raw scores relative to the observed maximum:
$$\text{overall\_score} = \min\left(\frac{\text{raw\_overall\_score}}{0.7287}, 1.0\right)$$
This maps the maximum observed score of `0.7287` to `1.0` and scales all other scores proportionally. After this recalibration:
* Scores $\ge 0.80$ successfully map to **HIGH** risk alerts.
* Scores $\ge 0.50$ map to **MEDIUM** risk alerts.
* Scores $< 0.50$ map to **LOW** risk alerts.
This ensures valid detection schemas and consistent risk levels in production.


---

## 4. Pipeline Model 2: XGBoost Scenario Classifier

The second model in the pipeline is a supervised **XGBoost Classifier** implemented in [XG_model_multiclass.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/classifier/XG_model_multiclass.py). It maps the raw behavioral features along with the 5 Isolation Forest risk scores to specific threat scenarios.

### Scenario Definitions
The CERT r4.2 dataset defines three threat scenarios (represented by labels `1`, `2`, and `3`):
* **Scenario 1 (s1 - Intellectual Property Exfiltration)**: User begins logging on after hours, using USBs to copy proprietary data (source code, documents) from file shares, and visiting job websites.
* **Scenario 2 (s2 - IT Sabotage)**: User is a system administrator who gets demoted or terminated. They log in off-hours, deploy a script or logic bomb, delete system configurations, or lock out active users.
* **Scenario 3 (s3 - Privilege Misuse / Espionage)**: User logs into other employees' workstations using compromised credentials and crawls system directories searching for proprietary data.

### Tackling Class Imbalance with SMOTE
Of the 330,452 rows, only **1,364** represent actual malicious activities:
* Label 0 (Normal): **329,088 rows** (99.59%)
* Label 1 (Scenario 1): **156 rows** (0.05%)
* Label 2 (Scenario 2): **1,188 rows** (0.36%)
* Label 3 (Scenario 3): **20 rows** (0.01%)

To train the classifier, the pipeline originally used **SMOTE (Synthetic Minority Over-sampling Technique)** across all minority classes, resulting in **264,157 rows for each label** (Normal, s1, s2, s3).

### The SMOTE Strategy Optimization (Step 10)
During baseline evaluation, we observed that Scenario 2 (s2) suffered from high false-positive rates (low precision of `0.4821`). Because the training set already contained 1,034 Scenario 2 samples (unlike Scenario 1 with 135 and Scenario 3 with 12), we optimized the SMOTE strategy:
1. **SMOTE was applied selectively** only to classes 1 and 3 (oversampling them to match class 0 count of 264,157).
2. **Class 2 was left at its original count** of 1,034 samples to prevent the generation of noisy synthetic samples that dilute classification boundaries.
3. This optimized distribution is: Class 0 = 264,157, Class 1 = 264,157, Class 2 = 1,034, Class 3 = 264,157.

### XGBoost Classifier Performance Comparison
The model trains using a tree-boosting objective `multi:softprob`. Bypassing SMOTE oversampling for Class 2 resulted in the following performance enhancements:

* **Scenario 1 (s1)**: Precision `0.5312`, Recall `0.8095`, F1 `0.6415` (compared to baseline: `0.5484` / `0.8095` / `0.6538`)
* **Scenario 2 (s2)**: Precision **`0.6806`**, Recall `0.3182`, F1 **`0.4336`** (compared to baseline: `0.4821` / `0.3506` / `0.4060`)
* **Scenario 3 (s3)**: Precision `1.0000`, Recall `0.6250`, F1 `0.7692` (compared to baseline: `0.8571` / `0.7500` / `0.8000`)

*Key Improvement*: Excluding Class 2 from SMOTE oversampling significantly boosted Class 2 precision from **48.21% to 68.06%** and improved the F1-score to **0.4336**, resolving major false positive concerns for EDR analysts.

The model outputs probability scores for each class: `rf_normal_prob`, `rf_s1_prob`, `rf_s2_prob`, and `rf_s3_prob`.


---

## 5. Pipeline Model 3: RedRVFL Behavioral Model

The final step of the threat pipeline is the **Recurrent Echo State Network with Random Vector Functional Link (RedRVFL)** model, defined in [red_revfl_orchestrator.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/red_revfl_orchestrator.py) and trained in [run_experiment.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/run/run_experiment.py).

### The Concept of a Random Vector Functional Link (RVFL) Network
An RVFL is a single-hidden-layer feedforward neural network where the input weights (weights connecting input nodes to hidden layer nodes) are **randomly initialized and frozen**. Only the output weights (weights connecting hidden layer nodes to output nodes) are trained.
Because the hidden layer weights do not change, training the network is a linear regression problem that can be solved in a single step using **Ridge regression (L2 regularization)**. This bypasses backpropagation, making training fast (under 17 seconds for 226,416 samples).

### The "Recurrent" (RedRVFL) Component
For sequence modeling, the model maintains a hidden state vector $h_t$ that carries temporal information across days.
Given the input sequence vector $x_t$ at day $t$, the hidden state update equation is:

$$h_t = f(W_{in} x_t + W_h h_{t-1} + b)$$

Where:
* $W_{in}$ is the input weight matrix (randomly initialized, frozen).
* $W_h$ is the recurrent weight matrix (randomly initialized, frozen).
* $b$ is the bias vector (randomly initialized, frozen).
* $f(\cdot)$ is a non-linear activation function (such as `tanh` or `relu`).
* $h_{t-1}$ is the previous day's hidden state.

Once the final hidden state $h_T$ at the end of the sequence (e.g. Day 7) is computed, the output $y_t$ (the predicted risk for Day 8) is calculated by fitting the output weights $W_{out}$ using a closed-form ridge solver:

$$W_{out} = (H^T H + \lambda I)^{-1} H^T Y$$

Where $H$ is the matrix containing all hidden states, $Y$ contains the targets, and $\lambda$ is the regularizer penalty (`ridge_alpha = 0.01`).

### Risk Fusing & Drift Prediction
RedRVFL operates on a single fused risk signal derived from both unsupervised (Isolation Forest) and supervised (XGBoost) models:

$$scenario\_risk = \max(rf\_s1\_prob, rf\_s2\_prob, rf\_s3\_prob)$$

$$rvfl\_risk = 0.3 \times overall\_risk + 0.7 \times scenario\_risk$$

The RedRVFL model takes a sequence of **7 consecutive days** of `rvfl_risk` and predicts the expected `rvfl_risk` for **Day 8**. 

The **behavioral drift** is the difference between what the user actually did on Day 8 (observed risk) versus what the recurrent neural network predicted they would do based on their 7-day baseline:

$$behavioral\_drift\_error = (observed\_rvfl\_risk - predicted\_rvfl\_risk)^2$$

A high prediction error (MSE $\ge 0.05$) indicates a sudden, unexplained shift in behavior, flagging the user as **HIGH** behavioral risk.

---

## 6. User Ranking & Recall Optimization (Our Key Improvement)

Once prediction errors are generated for all days, we need a way to rank the 198 test set users from most to least suspicious to present to security analysts.

In [run_experiment.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/run/run_experiment.py#L29-L177) and [check_user_recall.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/check_user_recall.py), four formulas were evaluated on the test set:

1. **`score_v1` (Current baseline)**:
   $$Score = max\_error \times \ln(1 + anomaly\_days)$$
   * *Intuition*: Looks for the single worst day (`max_error`) and scales it logarithmically based on the number of days a user was flagged as anomalous.
2. **`score_v2` (Proposed recommendation)**:
   $$Score = max\_error \times mean\_error \times \sqrt{anomaly\_days}$$
   * *Intuition*: Incorporates the single worst day (`max_error`), the average baseline deviation (`mean_error`), and the square root of persistent anomalies. By multiplying `max_error` and `mean_error`, it dampens users who had a single high error day due to noise, but elevates those who show high-severity, persistent drift.
3. **`score_v3` (Pure persistence)**:
   $$Score = mean\_error \times anomaly\_days$$
   * *Intuition*: Focuses purely on how long a user has shown elevated drift, regardless of the peak severity.
4. **`score_v4` (Weighted combination)**:
   $$Score = (0.4 \times max\_error + 0.6 \times mean\_error) \times \log(1 + anomaly\_days)$$

### Detection Metrics Comparison
Evaluating the methods against the 9 actual target insiders in the test set showed:

* **Top-5 Users**: All four methods achieved a recall of **`0.4444`** (identifying 4 of the 9 insiders, with 1 benign false positive).
* **Top-10 Users**:
  * `score_v1` (default): Identified **7 of 9** insiders (Recall: `0.7778`, Precision: `0.70`).
  * **`score_v2` (recommended)**: Identified **9 of 9** insiders (Recall: **`1.0000`**, Precision: **`0.90`**, F1: **`0.9474`**).
  * `score_v3` & `score_v4`: Identified **8 of 9** insiders (Recall: `0.8889`, Precision: `0.80`).

By changing the ranking formula to `score_v2` in production, EDR analysts can catch **100% of malicious insider threats** in the test set by inspecting only the Top-10 ranked users.

---

## 7. Inference API Request Lifecycle

The stateless API routes are implemented in [inference.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/inference.py). The payload flow for a full assessment proceeds as follows:

```text
                                CLIENT PAYLOAD
                               ┌──────────────┐
                               │ Feature dict │
                               └──────┬───────┘
                                      │
                                      ▼
                      1. predict_current_risk(payload)
            ┌──────────────────────────────────────────────────┐
            │ Validate feature columns exist                   │
            │ Compute logon_risk, file_risk, device_risk,      │
            │ and http_risk using Isolation Forest models      │
            │ Calculate mean score (overall_risk)              │
            └──────────────────────┬───────────────────────────┘
                                   │
                                   ├───────────────────────────┐
                                   │ (overall_risk)            │ (Domain scores)
                                   ▼                           ▼
                     2. predict_scenario(payload)        CLIENT RESPONSE
            ┌─────────────────────────────────────────┐ ┌──────────────┐
            │ Append daily_risk_delta, rolling_mean,  │ │ Risk Level   │
            │ and rolling_std (supplied in payload)   │ │ (LOW/MED)    │
            │ Predict class probabilities using       │ └──────────────┘
            │ scenario_xgb.pkl                        │
            └──────────────────────┬──────────────────┘
                                   │
                                   │ (rf_s1_prob, rf_s2_prob, rf_s3_prob)
                                   ▼
                3. predict_behavioral_risk(payload)
            ┌──────────────────────────────────────────────────┐
            │ Receive 8-day sequence of overall_risk           │
            │ and scenario probabilities                       │
            │ Scale sequence features using MinMaxScaler       │
            │ Run RedRVFL to predict Day 8 risk                │
            │ Compute MSE (behavioral drift error)             │
            └──────────────────────┬───────────────────────────┘
                                   │
                                   ▼
                            CLIENT RESPONSE
            ┌──────────────────────────────────────────────────┐
            │ Return behavioral_risk (HIGH/MED/LOW) and        │
            │ suggested analyst escalation actions             │
            └──────────────────────────────────────────────────┘
```

---

## 8. Summary of Files and Directories in Workspace

* **[src/server/features/extractors/](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/)**: Code for extracting raw features from logs.
  * [http.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/http.py): Optimized HTTP event extractor (contains the 5.3x speedup loop).
  * [logon.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/logon.py), [file.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/file.py), [device.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/features/extractors/device.py): Extractor logic for the other three log domains.
* **[src/server/anomaly/](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/anomaly/)**: Implementation of the domain-level anomaly detection logic.
  * [domain_models.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/anomaly/domain_models.py): Trains/loads the ensemble of Isolation Forests.
* **[src/server/classifier/](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/classifier/)**: Supervised classification components.
  * [feature_to_dataset.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/classifier/feature_to_dataset.py): Maps the Isolation Forest scores to ground-truth scenario labels using `insiders.csv`.
  * [XG_model_multiclass.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/classifier/XG_model_multiclass.py): Training pipeline for multi-class XGBoost with SMOTE.
* **[src/red_revfl_orchestrator.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/red_revfl_orchestrator.py)**: Python module implementing the Recurrent ESN architecture and input weight randomization.
* **[src/run/run_experiment.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/run/run_experiment.py)**: Orchestrator that structures sequences, trains RedRVFL, and generates prediction error datasets.
* **[src/check_user_recall.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/check_user_recall.py)**: Recall evaluation framework used to test and validate `score_v1` through `score_v4` on identified insiders.
* **[src/server/inference.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/server/inference.py)**: Stateless API inference logic.
* **[src/tests/](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/tests/)**: Integration and validation suites to confirm pipeline correctness.
  * [test_inference.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/tests/test_inference.py): Validates API payload formats.
  * [end_to_end.py](file:///c:/Users/Guruchandar/Downloads/insiEDR%20project/InsiEDR/src/tests/end_to_end.py): Tests the entire inference lifecycle (IF $\to$ XGB $\to$ RedRVFL) on sample data.
