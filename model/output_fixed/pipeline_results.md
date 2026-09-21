# Full Pipeline Results: Fixed Labeling (trailing_days=10) + SMOTE

## XGBoost Classification Report

| Class | Precision | Recall | F1-Score | Support |
|:---|:---:|:---:|:---:|:---:|
| normal | 0.9999 | 0.9997 | 0.9998 | 12,686 |
| email_exfil | 0.8261 | 0.9500 | 0.8837 | 20 |
| sabotage | 1.0000 | 1.0000 | 1.0000 | 20 |
| usb_exfil | 1.0000 | 1.0000 | 1.0000 | 20 |
| flight_risk | 0.9524 | 1.0000 | 0.9756 | 20 |
| cloud_exfil | 1.0000 | 0.9500 | 0.9744 | 20 |
| **Macro avg** | **0.9631** | **0.9833** | **0.9722** | 12,786 |

---

## XGBoost Confusion Matrices

### 6-Class Multiclass Confusion Matrix
![XGBoost 6-Class Confusion Matrix — Fixed labeling correctly separates all 5 threat scenarios with minimal confusion. Only 5 total misclassifications across 12,786 test rows.](./confusion_matrices/xgb_multiclass_cm.png)

### Row-Normalized (Recall-Oriented) Matrix
![Normalized confusion matrix showing per-class recall rates. All threat classes achieve 95-100% recall, meaning almost every insider day is correctly classified.](./confusion_matrices/xgb_multiclass_cm_normalized.png)

### Binary Confusion Matrix (Normal vs Insider)
![Binary confusion matrix — 99 out of 100 insider test days detected, with only 4 false positives out of 12,686 normal days.](./confusion_matrices/xgb_binary_cm.png)

---

## Per-Scenario One-vs-Rest Matrices

![email_exfil vs Normal — 19/20 correctly detected, 1 missed. 4 normal days misclassified as email_exfil.](./confusion_matrices/xgb_email_exfil_vs_normal_cm.png)

![sabotage vs Normal — Perfect 20/20 detection with zero false positives.](./confusion_matrices/xgb_sabotage_vs_normal_cm.png)

![usb_exfil vs Normal — Perfect 20/20 detection with zero false positives.](./confusion_matrices/xgb_usb_exfil_vs_normal_cm.png)

![flight_risk vs Normal — Perfect 20/20 detection, but 1 normal day misclassified.](./confusion_matrices/xgb_flight_risk_vs_normal_cm.png)

![cloud_exfil vs Normal — 19/20 detected, 1 missed. Zero false positives.](./confusion_matrices/xgb_cloud_exfil_vs_normal_cm.png)

---

## End-to-End Pipeline Impact (IF -> XGBoost -> RedRVFL)

### Top-K Detection Performance

![Top-K detection chart showing recall, precision, and F1 across review queue sizes. 100% recall achieved at Top-15.](./confusion_matrices/pipeline_top_k_chart.png)

| Top-K | TP | FP | FN | Recall | Precision | F1 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **5** | 5 | 0 | 5 | 50.00% | **100.00%** | 0.6667 |
| **10** | 9 | 1 | 1 | 90.00% | 90.00% | **0.9000** |
| **15** | **10** | 5 | **0** | **100.00%** | 66.67% | 0.8000 |
| 20 | 10 | 10 | 0 | 100.00% | 50.00% | 0.6667 |
| 25 | 10 | 15 | 0 | 100.00% | 40.00% | 0.5714 |

### Insiders Detected by Rank
| Rank | User | Scenario |
|:---:|:---|:---|
| 1–5 | U0604, U0430, U0719, U0143, U0349 | email_exfil, cloud_exfil(×2), email_exfil, sabotage |
| 6–9 | U0028, U0891, U0221, U0282 | usb_exfil, sabotage, flight_risk(×2) |
| 10–15 | U0229 + 5 false positives | usb_exfil (last insider found at rank ~11–15) |

### Pipeline User-Level Confusion Matrix (at Top-15)
![End-to-end pipeline user-level confusion matrix at Top-15 — all 10 insiders caught with 5 false alarms.](./confusion_matrices/pipeline_user_cm.png)
