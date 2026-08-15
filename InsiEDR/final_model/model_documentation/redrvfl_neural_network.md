# RedRVFL Behavioral Sequence Drift Model

## 1. Model Overview
The RedRVFL model is Level 3 of the InsiEDR pipeline. It analyzes how a user's risk score **changes over time** rather than just what the score is on a given day. By learning each user's normal behavioral patterns across a 7-day sliding window, it detects when someone starts behaving in an unusual or drifting way — a strong signal of sustained insider threat activity.

This model does not reclassify threat types. Its job is to measure **how far a user has deviated from their own past behavior**, which catches threats that develop gradually and might be missed by single-day models.

---

## 2. Input Data Fed into the Model

The model operates on **sequences of daily risk values** per user:

### Fused Risk Signal (computed per user per day):
- A single combined score: `rvfl_risk = 0.3 × overall_risk + 0.7 × scenario_risk`
  - `overall_risk`: Weighted anomaly score from Isolation Forest (Level 1).
  - `scenario_risk`: Threat confidence score from XGBoost (Level 2).

### Sequence Structure:
- For each user, the model collects their `rvfl_risk` scores over the last **7 days**.
- This 7-day window forms a sequence: `[day1, day2, day3, day4, day5, day6, day7]`.
- The model is given days 1–6 as input and asked to predict day 7.

### Requirements:
- A user must have **at least 7 days** of activity data to be evaluated.
- Users with fewer days are excluded.

---

## 3. How the Model Works

1. **Random LSTM Layers**: The model uses 5 stacked LSTM-style layers with randomly initialized weights that are **never updated during training**. These layers transform the input sequence into a rich set of internal representations.
2. **Closed-Form Ridge Regression**: Only the final output layer is trained, using a mathematical formula (Ridge Regression with regularization strength 0.01). This makes training very fast and avoids overfitting.
3. **Behavioral Baseline**: The model learns what a "normal" sequence of daily risk scores looks like for each user during the training period.
4. **Drift Detection**: At test time, the model predicts what the next day's risk should be. If the actual value is very different from the prediction, it means the user's behavior has drifted from their norm.
5. **Error Scoring**: The prediction error is computed for each day in a user's test window. Users with consistently high errors — meaning their behavior keeps deviating from expectations — receive a high final score.

---

## 4. Output of the Model

For every user evaluated, the model outputs:

- `max_error`: The single largest prediction error across all days. Captures sudden behavioral spikes.
- `mean_error`: The average prediction error across all evaluated days. Captures sustained drift.
- `n_days`: Number of days used in the evaluation.
- `score_v2`: Final user-level threat score, calculated as: `max_error × mean_error × √n_days`. Higher scores indicate stronger and more sustained behavioral drift.
- **Ranking**: All users are ranked by `score_v2`. The top-ranked users are the most likely insiders.
- **Top-K Evaluation**: The pipeline checks how many known insiders are captured within the Top-10, Top-20, Top-50 ranked users.
  - Achieved result: 100% insider recall within the Top-10 (all 10 insiders caught, zero false positives).
