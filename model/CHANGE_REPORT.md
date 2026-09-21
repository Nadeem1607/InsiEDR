# XGBoost Labeling Fix & SMOTE Addition — Change Report

## Summary of Changes

This branch fixes a **data labeling bug** in the XGBoost training pipeline (`model/run_new_model.py`) and replaces naive random oversampling with proper **SMOTE** (Synthetic Minority Oversampling Technique).

---

## 1. The Bug: Incorrect Day-Level Labeling (`trailing_days=None`)

### What Was Wrong

In `model/run_new_model.py`, the `create_labels()` function was called with `trailing_days=None` at two locations (previously lines 306 and 343). When `trailing_days=None`, **every single day** of an insider user's timeline was labeled with their threat class (e.g., `cloud_exfil`, `sabotage`), even though the insider only exhibited malicious behavior during a small window near the end of their timeline.

For example, insider user U0430 (`cloud_exfil`) had ~67 active days. Under the buggy labeling, all 67 days were labeled as Class 5 (`cloud_exfil`), including early days when U0430 was behaving **completely normally**. The XGBoost model was effectively trained to recognize "being user U0430" rather than "exhibiting cloud exfiltration behavior."

### What Was Fixed

Changed both calls to use `trailing_days=10`:

```python
# Before (buggy)
labeled_df_if = create_labels(feature_df, labels_df, trailing_days=None)
labeled_df_new = create_labels(feature_df, labels_df, trailing_days=None)

# After (fixed)
labeled_df_if = create_labels(feature_df, labels_df, trailing_days=10)
labeled_df_new = create_labels(feature_df, labels_df, trailing_days=10)
```

This ensures only the **last 10 active days** per insider user are labeled with their threat scenario. All earlier days of insider users are excluded from training/evaluation (marked as `label=-1`), preventing the model from learning user identity as a proxy signal.

### Impact on Dataset Size

| Metric | Buggy (`None`) | Fixed (`10`) |
|:---|:---:|:---:|
| Total valid rows | 67,112 | 63,856 |
| Normal (Class 0) rows | 63,356 | 63,356 |
| Insider rows per class | ~750 (all days) | 100 (last 10 days × 10 users) |
| Excluded insider days (`label=-1`) | 0 | 3,256 |

---

## 2. Oversampling: Random Duplication → SMOTE

### What Was Wrong

The original code (lines 358–378) used **naive random oversampling** via `pd.DataFrame.sample(replace=True)`. This simply duplicated exact existing rows from minority classes to match the majority class count. With the buggy labeling, this meant thousands of copies of normal-behavior rows that were mislabeled as threats.

### What Was Fixed

Replaced with `imblearn.over_sampling.SMOTE`:

```python
from imblearn.over_sampling import SMOTE

sampling_strategy = {c: class_0_count for c in range(1, 6) if c in train_dist.index}
smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=3)
X_train_smote, y_train_smote = smote.fit_resample(X_train_xgb, y_train_xgb)
```

SMOTE generates **synthetic interpolated samples** by finding k-nearest neighbors in the minority class and creating new data points along the line segments between them. This produces more diverse training examples than exact row duplication.

### Practical Impact of SMOTE on XGBoost

As expected for a tree-based model, SMOTE alone is not the primary driver of improvement here. XGBoost handles class imbalance reasonably well through its histogram-based splits. The dominant performance improvement came from the **labeling fix**. SMOTE provides a marginal benefit by reducing overfitting to specific insider user feature patterns.

---

## 3. Results Comparison

### XGBoost Scenario Classification (Test Split)

| Metric | Buggy (all days) | Fixed (last 10 days + SMOTE) |
|:---|:---:|:---:|
| **Macro F1** | 0.6164 | **0.9722** |
| **Accuracy** | 0.9638 | **0.9995** |
| email_exfil Recall | 0.3289 | **0.9500** |
| sabotage Recall | 0.4027 | **1.0000** |
| usb_exfil Recall | 0.3922 | **1.0000** |
| flight_risk Recall | 0.4106 | **1.0000** |
| cloud_exfil Recall | 0.3933 | **0.9500** |
| Binary FN (missed insiders) | 460 | **1** |
| Binary FP (false alarms) | 24 | 4 |

### End-to-End Pipeline (IF → XGBoost → RedRVFL)

| Top-K | Recall | Precision | F1 |
|:---:|:---:|:---:|:---:|
| Top-5 | 50.00% | 100.00% | 0.6667 |
| **Top-10** | **90.00%** | **90.00%** | **0.9000** |
| Top-15 | 100.00% | 66.67% | 0.8000 |

### Why the Bug *Hurt* Performance Rather Than Inflating It

Counter-intuitively, the buggy labeling did not inflate metrics — it **destroyed** insider recall. When all ~75 days of an insider are labeled as their threat class, ~85% of those "threat" rows have **normal-looking features** (because the user was behaving normally on those days). This creates massive label noise:

- The model sees identical feature distributions across Class 0 (normal users) and Classes 1–5 (insider users' normal days), making it unable to learn a clean decision boundary.
- Insider recall dropped to 33–41% because the test set also contained these normal-behavior days with threat labels, and the model correctly predicted them as "normal" — but the evaluation counted that as a miss.

With the fix, only the 10 genuinely anomalous days are labeled, so the model sees a clean signal and can separate threat behaviors sharply.

---

## 4. Critical Caveats — Why These Results May Be Misleadingly Good

> **The near-perfect XGBoost metrics (0.97+ F1) should be viewed with skepticism.**

### A. Synthetic Data Simplicity

The synthetic dataset generates threat scenarios using **deterministic, extreme behavioral signatures** (e.g., sudden spikes in off-hours USB usage for `usb_exfil`, bulk file downloads for `cloud_exfil`). These signatures are designed to be clearly distinguishable from normal behavior. In real-world EDR telemetry:

- Insider threats are subtle, gradual, and often overlap heavily with legitimate behavior patterns.
- There is no clean 10-day "attack window" — malicious activity is interleaved with normal work.
- Feature distributions for insiders and normal users overlap significantly.

The XGBoost model is essentially separating **trivially distinct clusters** in feature space. This does not prove the model can handle the nuance of real-world insider threat detection.

### B. Trailing-Window Labeling Is Still a Heuristic

The `trailing_days=10` approach assumes the last 10 active days are the malicious days. Without per-day ground-truth timestamps, there is no guarantee this assumption is correct. If the actual attack happened on days 5–15 of a 67-day timeline, the model is still training on the wrong days.

### C. Small Cohort Volatility

The test split contains only **10 insiders** out of 200 users. A single user changing rank alters recall by 10 percentage points. These metrics are highly sensitive to the specific random split and do not prove stable generalization.

### D. What Would Give More Confidence

1. **Cross-validation with multiple random seeds** (5+ splits) to confirm stability of Top-K recall.
2. **Testing on an independent, non-synthetic dataset** where the model has never seen any telemetry from target users.
3. **Sensitivity analysis on window sizes** (5, 15, 20, 30, 45 days) to measure how label quality affects the boundary.
4. **Feature ablation studies** — removing the most discriminative features to see if performance degrades gracefully or collapses (a sign of trivial separation).
5. **Adversarial noise injection** — adding realistic noise to the synthetic data to simulate overlapping distributions.

---

## 5. Files Changed

### Modified
- `model/run_new_model.py` — Labeling fix + SMOTE replacement (3 changes: import, line 307, lines 344 and 359–367)

### Added
- `model/output_fixed/` — All new evaluation artifacts:
  - `pipeline_results.md` — Comprehensive results report with charts
  - `confusion_matrices/` — 11 rendered PNG heatmaps (multiclass, binary, per-scenario, Top-K chart, pipeline user-level)
  - `xgb_model_fixed.pkl` — Retrained XGBoost model
  - `xgb_classification_report.txt` — Text classification report
  - `xgb_multiclass_confusion_matrix.csv` — 6×6 confusion matrix
  - `xgb_binary_confusion_matrix.csv` — Normal vs Insider confusion matrix
  - `pipeline_top_k_results.csv` — End-to-end Top-K metrics
  - `user_rankings_fixed.csv` — All 1,000 users ranked by risk score
  - `pipeline_user_confusion_matrix.csv` — User-level confusion matrix at optimal K

### Dependencies
- `imbalanced-learn` (provides `imblearn.over_sampling.SMOTE`) — add to `requirements.txt` if not already present.
