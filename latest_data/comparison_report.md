# InsiEDR Model Pipeline Performance Comparison

## Executive Summary
This report compares the performance of the InsiEDR pipeline using the `score_v2` ranking metric ($max\_error \times mean\_error \times \sqrt{anomaly\_days}$) on the original CERT r4.2 dataset vs. the newly adapted dataset.

> [!WARNING]
> **Important Caveat**: The Isolation Forest anomaly scoring thresholds and the label density differ significantly between these two datasets. In particular, the new dataset contains 5% target insider users in the test set (10/200), whereas the old CERT r4.2 dataset contained ~4.5% (9/198). Furthermore, threat day definitions differ. Therefore, these recall, precision, and F1-score comparisons are not strictly apples-to-apples, but rather serve as a baseline transfer sanity-check.

## Side-by-Side Metrics Table

| Dataset / Metric | Top-5 Review Queue | Top-10 Review Queue | Top-25 Review Queue |
| :--- | :---: | :---: | :---: |
| **CERT r4.2 (Old) Recall** | 0.4444 (4/9) | **1.0000** (9/9) | 1.0000 (9/9) |
| **New Dataset Recall** | 0.5000 (5/10) | **0.9000** (9/10) | 1.0000 (10/10) |
| | | | |
| **CERT r4.2 (Old) Precision** | 0.8000 | **0.9000** | 0.3600 |
| **New Dataset Precision** | 1.0000 | **0.9000** | 0.4000 |
| | | | |
| **CERT r4.2 (Old) F1-Score** | 0.5714 | **0.9474** | 0.5294 |
| **New Dataset F1-Score** | 0.6667 | **0.9000** | 0.5714 |

## Detailed Rankings of Test Split Insiders

Here is where the 10 target test insiders ended up in the final ranked list:

| Rank | User ID | Threat Scenario | `score_v2` |
| --- | --- | --- | --- |
| 1 | U0604 | email_exfil | 0.216461 |
| 2 | U0430 | cloud_exfil | 0.206198 |
| 3 | U0719 | cloud_exfil | 0.196719 |
| 4 | U0143 | email_exfil | 0.128606 |
| 5 | U0349 | sabotage | 0.121770 |
| 6 | U0028 | usb_exfil | 0.109610 |
| 7 | U0891 | sabotage | 0.108955 |
| 8 | U0221 | flight_risk | 0.103583 |
| 10 | U0282 | flight_risk | 0.042845 |
| 12 | U0229 | usb_exfil | 0.011829 |