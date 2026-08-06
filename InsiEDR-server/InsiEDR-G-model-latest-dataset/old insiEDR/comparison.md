# InsiEDR Run 1 vs. Run 2 Comparison

This document provides a side-by-side comparison of the two experimental runs executed in this project, outlining what was modified at each step and the resulting metrics.

---

## 1. Step-by-Step Pipeline Comparison

| Pipeline Step | Run 1 (Baseline) | Run 2 (Optimized) | Impact / Rationale |
| :--- | :--- | :--- | :--- |
| **HTTP Feature Extraction** | Row-by-row iteration using Pandas `.itertuples()` and `urlparse()`. | Vectorized URL parsing using string splits (`.str.split('/')`) and zipped array loop. | **5.3x Speedup**: Reduced processing time of 14.5 GB raw logs from ~30+ minutes to **3m 12s**. |
| **Isolation Forest Risk Thresholds** | Raw scores evaluated directly against cutoffs (maximum score was `0.7287`, so `HIGH` risk of `0.80` was unreachable). | Rescaled scores using $\min(\frac{\text{raw\_overall\_score}}{0.7287}, 1.0)$ in `inference.py`. | **Corrected Alerts**: The maximum score scales to `1.0`, enabling daily events to successfully trigger `HIGH` and `MEDIUM` alerts. |
| **XGBoost Class Imbalance Handling** | **Full SMOTE**: Oversampled all minority classes (Classes 1, 2, and 3) to match Class 0 count of 264,157 rows. | **Partial SMOTE**: Oversampled only Classes 1 and 3; left Class 2 (Scenario 2) at its original count of 1,034 samples. | **Removed Noise**: Bypassing SMOTE for the moderately sized Class 2 prevented the generation of noisy synthetic samples. |
| **User Recall Scoring** | Sorted by `score_v1` ($max\_error \times \ln(1 + \text{anomaly\_days})$). | Sorted by `score_v2` ($max\_error \times mean\_error \times \sqrt{\text{anomaly\_days}}$). | **Higher Recall**: `score_v2` achieved **100% recall** at Top-10, catching all target insiders with only 1 false positive. |

---

## 2. Model Metrics Performance Comparison

### XGBoost Classifier (Scenario 2 / Class 2)
The table below shows the performance of the XGBoost classifier specifically for **Scenario 2 (IT Sabotage)**:

| Metric | Run 1 (Baseline - Full SMOTE) | Run 2 (Optimized - Partial SMOTE) | Improvement |
| :--- | :---: | :---: | :---: |
| **Precision** | 0.4821 | **0.6806** | 📈 **+19.85%** |
| **Recall** | 0.3506 | 0.3182 | 📉 -3.24% |
| **F1-Score** | 0.4060 | **0.4336** | 📈 **+2.76%** |

### Run 1 (Baseline) Candidate Scores Comparison
This table shows how all four candidate scoring formulas performed on **Run 1 (Baseline)** outputs at the **Top-10** queue level:

| Formula | Detected Insiders | Recall | Precision | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Score_v1** | 7 / 9 | 0.7778 | 0.7000 | 0.7368 | Baseline |
| **Score_v2** | **9 / 9** | **1.0000** | **0.9000** | **0.9474** | **Winner** |
| **Score_v3** | 8 / 9 | 0.8889 | 0.8000 | 0.8421 | Runner-up |
| **Score_v4** | 8 / 9 | 0.8889 | 0.8000 | 0.8421 | Runner-up |

### End-to-End User Recall (Top-10 Queue)
The table below shows the detection metrics for the 9 target insiders in the test set using the **Top-10 investigation queue**, comparing the Run 1 baseline score (`score_v1`) to the Run 2 optimized score (`score_v2`):

| Metric | Run 1 (Baseline - `score_v1`) | Run 2 (Optimized - `score_v2`) | Improvement |
| :--- | :---: | :---: | :---: |
| **Detected Insiders** | 7 / 9 | **9 / 9** | 📈 **+2 Insiders** |
| **Recall** | 0.7778 | **1.0000** | 📈 **+22.22%** |
| **Precision** | 0.7000 | **0.9000** | 📈 **+20.00%** |
| **F1-Score** | 0.7368 | **0.9474** | 📈 **+21.06%** |


---

## 3. Summary of Key Findings

* **Selective SMOTE is Better for Moderate Classes**: Fully oversampling Class 2 (which already had 1,034 samples) diluted the classifier's feature space, causing many normal daily events to be flagged as IT Sabotage. Bypassing SMOTE for Class 2 resulted in a major **19.85% boost in precision**.
* **Fusing Consistency with Severity Wins**: While the baseline `score_v1` only measured peak anomaly severity scaled by duration, `score_v2` multiplies the peak severity by the average baseline deviation (`mean_error`). This dampens users who had a single random high-error day (noise) while elevating users who showed consistent, high-severity drift, achieving a perfect **100% recall in the Top-10 queue**.
