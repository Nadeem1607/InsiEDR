# InsiEDR 7-Step Pipeline Data Flow Mind Map

This document visualizes the complete data flow, training process, and file transformations across all 7 steps of the InsiEDR endpoint detection pipeline.

---

## 1. Pipeline Flow Diagram

```mermaid
flowchart TD
    %% Styling Classes
    classDef inputStyle fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#000;
    classDef processStyle fill:#cfe2ff,stroke:#0d6efd,stroke-width:2px,color:#000;
    classDef outputStyle fill:#d1e7dd,stroke:#198754,stroke-width:2px,color:#000;
    classDef modelStyle fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#000;

    %% STEP 1: Extraction
    raw_bz2["r4.2.tar.bz2<br>(Raw Dataset Archive)"]:::inputStyle
    tar_extract["tar -xjf Archive Extraction"]:::processStyle
    raw_logs["Raw Log CSVs<br>(logon.csv, file.csv, device.csv, http.csv)"]:::outputStyle
    insiders_timeline["insiders.csv<br>(Threat Timeline Answers)"]:::outputStyle
    
    raw_bz2 --> tar_extract
    tar_extract --> raw_logs
    tar_extract --> insiders_timeline

    %% STEP 2: Feature Extraction
    vectorized_parsing["Vectorized URL split & zipped aggregation in http.py"]:::processStyle
    other_parsers["Logon, File, Device parser scripts"]:::processStyle
    feature_df["In-Memory feature_df<br>(Daily user activity stats)"]:::outputStyle
    
    raw_logs --> vectorized_parsing & other_parsers
    vectorized_parsing & other_parsers --> feature_df

    %% STEP 3: Domain Isolation Forests
    schema_slicing["feature_schema.py lists<br>(LOGON/FILE/DEVICE/HTTP schemas)"]:::processStyle
    domain_matrices["Domain Slicing:<br>logon_X, file_X, device_X, http_X"]:::processStyle
    if_logon["Logon Isolation Forest"]:::processStyle
    if_file["File Isolation Forest"]:::processStyle
    if_device["Device Isolation Forest"]:::processStyle
    if_http["HTTP Isolation Forest"]:::processStyle
    avg_score["Raw overall_risk = average(domain scores)"]:::processStyle
    if_recal["Threshold Recalibration:<br>overall_score = min(raw / 0.7287, 1.0)"]:::processStyle
    if_model["models/domain_isolation_forest.pkl"]:::modelStyle
    if_enriched_csv["if_enriched_features.csv<br>(Original features + overall_risk)"]:::outputStyle

    feature_df --> schema_slicing --> domain_matrices
    domain_matrices -->|logon_X| if_logon
    domain_matrices -->|file_X| if_file
    domain_matrices -->|device_X| if_device
    domain_matrices -->|http_X| if_http
    if_logon & if_file & if_device & if_http --> avg_score --> if_recal
    if_recal --> if_enriched_csv
    if_recal --> if_model

    %% STEP 4: XGBoost Scenario Classifier
    map_labels["feature_to_dataset.py<br>(Match rows to insiders.csv threat window)"]:::processStyle
    scenario_training_csv["scenario_training_dataset.csv<br>(Labels: 0=Norm, 1=s1, 2=s2, 3=s3)"]:::outputStyle
    gss_split["GroupShuffleSplit by User ID<br>(80% Train Users / 20% Test Users)"]:::processStyle
    train_split["Train Split (X_train, y_train)"]:::processStyle
    test_split["Test Split (X_test, y_test)"]:::processStyle
    partial_smote["Partial SMOTE:<br>Oversample Classes 1 & 3;<br>Keep Class 2 at 1,034 samples"]:::processStyle
    xgb_fit["XGBClassifier.fit() tree boosting"]:::processStyle
    xgb_predict["Predict class probabilities on entire dataset"]:::processStyle
    xgb_model["models/scenario_xgb.pkl"]:::modelStyle
    xgb_enriched_csv["scenario_training_dataset_with_xgb.csv<br>(Adds rf_normal_prob, rf_s1_prob, rf_s2_prob, rf_s3_prob)"]:::outputStyle

    if_enriched_csv & insiders_timeline --> map_labels --> scenario_training_csv
    scenario_training_csv --> gss_split
    gss_split -->|Train Users| train_split --> partial_smote --> xgb_fit
    gss_split -->|Test Users (Unseen)| test_split
    xgb_fit --> xgb_predict
    test_split -->|Performance Evaluation| xgb_predict
    xgb_predict --> xgb_enriched_csv
    xgb_predict --> xgb_model

    %% STEP 5: RedRVFL Behavioral Model
    max_scenario["scenario_risk = max(rf_s1_prob, rf_s2_prob, rf_s3_prob)"]:::processStyle
    fuse_risk["rvfl_risk = 0.3 * overall_score + 0.7 * scenario_risk"]:::processStyle
    sequence_building["Build chronological 7-day sliding window sequences per user"]:::processStyle
    rvfl_fit["RedRVFL ESN network fit via Ridge Regression"]:::processStyle
    rvfl_predict["Predict day t risk & compute MSE error"]:::processStyle
    all_anomaly_csv["all_anomaly_days.csv<br>(user, date, error)"]:::outputStyle
    pred_errors_csv["prediction_errors.csv<br>(Raw error score list)"]:::outputStyle
    top_anomalies_csv["top_anomalies.csv<br>(Worst daily alerts)"]:::outputStyle
    user_stats["Calculate per-user stats:<br>- max_error (peak severity)<br>- mean_error (average deviation)<br>- anomaly_days (duration)"]:::processStyle
    score_v2_calc["Score_v2 = max_error * mean_error * sqrt(anomaly_days)"]:::processStyle
    top_users_csv["top_users.csv<br>(Ranked users by score_v2)"]:::outputStyle
    test_insiders_csv["test_insiders.csv<br>(List of test set threat users)"]:::outputStyle

    xgb_enriched_csv --> max_scenario --> fuse_risk --> sequence_building --> rvfl_fit --> rvfl_predict
    rvfl_predict --> all_anomaly_csv & pred_errors_csv & top_anomalies_csv
    rvfl_predict --> test_insiders_csv
    all_anomaly_csv --> user_stats --> score_v2_calc --> top_users_csv

    %% STEP 6: User Recall Ranking Evaluation
    recall_eval["check_user_recall.py<br>(Sorts users by score_v2 and matches with test_insiders)"]:::processStyle
    eval_logs["Evaluation print logs: logs/step9_score_v2.txt"]:::outputStyle
    
    top_users_csv & test_insiders_csv --> recall_eval --> eval_logs

    %% STEP 7: Integration & Validation
    test_inf["test_inference.py unit testing"]:::processStyle
    e2e_sim["end_to_end.py simulation on user payload"]:::processStyle
    validation_logs["Validation logs: logs/run_test_inference.txt & logs/end_to_end.txt"]:::outputStyle

    if_model & xgb_model --> test_inf & e2e_sim --> validation_logs
```


---

## 2. In-Depth Step Explanations (Inputs, Transforms, Outputs)

### Step 1: Dataset Extraction
* **Input Data**: `r4.2.tar.bz2` (compressed tarball archive of the CERT insider threat dataset).
* **Transformation**: Extracted using command line bzip compression utilities (`tar`).
* **Saved Outputs**: Raw event logs under `data/CERT/r4.2/r4.2/` (`logon.csv`, `file.csv`, `device.csv`, `http.csv`) and the ground truth threats under `data/CERT/r4.2/answers/answers/insiders.csv`.

### Step 2: Feature Extraction
* **Input Data**: Raw logon, file, device, and HTTP CSV logs.
* **Transformation**: Sliced and parsed by user and day. Optimized in `http.py` by converting slow loop-by-row lookups into vectorized string splitting (`.str.split('/')`) and zipped loop groupings.
* **Saved Outputs**: An in-memory Pandas DataFrame `feature_df` containing daily feature columns (logon count, USB connection count, volume of file reads, URL browsing count) mapped to `user` and `date`.

### Step 3: Domain Isolation Forests
* **Input Data**: In-memory `feature_df` (spliced into four independent matrices `logon_X`, `file_X`, `device_X`, `http_X` containing only domain-specific columns).
* **Transformation**: Fits four separate unsupervised `IsolationForest` models. For each daily record, it computes their raw average to get `overall_risk`. In `src/server/inference.py`, this is rescaled: $\text{overall\_score} = \min(\frac{\text{raw}}{0.7287}, 1.0)$ to map the maximum observed score of `0.7287` to `1.0`.
* **Saved Outputs**: 
  * `models/domain_isolation_forest.pkl` (trained ensemble model).
  * `if_enriched_features.csv` (contains original features plus `overall_risk` and individual domain risk scores).

### Step 4: XGBoost Scenario Classifier
* **Input Data**: `if_enriched_features.csv` and ground truth file `insiders.csv`.
* **Transformation**: 
  1. `feature_to_dataset.py` cross-references the features with the threat timeline, labeling each day as class `0` (Normal), `1` (IP Theft), `2` (IT Sabotage), or `3` (Keylogging), saving it as `scenario_training_dataset.csv`.
  2. `XG_model_multiclass.py` splits users into 80% train and 20% test using `GroupShuffleSplit` (avoiding data leakage).
  3. Applies partial SMOTE oversampling to training users (leaving Class 2 at its original count of 1,034). Trains the tree-boosting model, and outputs daily probability scores for all records.
* **Saved Outputs**:
  * `models/scenario_xgb.pkl` (trained classification model).
  * `scenario_training_dataset_with_xgb.csv` (dataset containing original features and new probability columns: `rf_normal_prob`, `rf_s1_prob`, `rf_s2_prob`, `rf_s3_prob`).

### Step 5: RedRVFL Behavioral Model
* **Input Data**: `scenario_training_dataset_with_xgb.csv`.
* **Transformation**:
  1. Fuses daily risk: $\text{rvfl\_risk} = 0.3 \times \text{overall\_risk} + 0.7 \times \max(\text{rf\_s1\_prob}, \text{rf\_s2\_prob}, \text{rf\_s3\_prob})$.
  2. Builds chronological 7-day sliding window sequences for each user.
  3. Trains a Recurrent Random Vector Functional Link (ESN) network via Ridge regression.
  4. Generates a daily prediction error (Mean Squared Error) indicating how much a user's behavior drifts from their normal sequence baseline.
* **Saved Outputs**:
  * `all_anomaly_days.csv` (daily chronological sequences: `user`, `date`, `error`).
  * `prediction_errors.csv` (flat list of error values).
  * `top_anomalies.csv` (ranked daily records with highest prediction errors).
  * `top_users.csv` (user-level aggregated statistics: `user`, `max_error`, `mean_error`, `anomaly_days`, and calculated user scores: `score_v1` to `score_v4`).
  * `test_insiders.csv` (list of actual insider usernames in the test set).

### Step 6: User Recall Ranking Evaluation
* **Input Data**: `top_users.csv` and `test_insiders.csv`.
* **Transformation**: Evaluates sorting users by different scoring formulas. Defaults to `score_v2` ($max\_error \times mean\_error \times \sqrt{anomaly\_days}$) to rank users and computes precision/recall/F1 metrics at Top-N review queues.
* **Saved Outputs**: Detailed print logs (`logs/step9_score_v2.txt`) showing **100% recall (9/9 insiders detected)** in the Top-10.

### Step 7: Integration & Validation
* **Input Data**: Trained model pickles (`domain_isolation_forest.pkl`, `scenario_xgb.pkl`).
* **Transformation**: Executes stateless detector unit tests and pipelines simulation using individual user payloads to ensure the entire EDR agent system is integrated and healthy.
* **Saved Outputs**: Pass validation logs saved under `logs/run_test_inference.txt` and `logs/end_to_end.txt`.
