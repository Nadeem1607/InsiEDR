# RedRVFL Behavioral Sequence Drift Neural Network — Technical Documentation

## 1. Model Overview

The **RedRVFL (Reduced Random Vector Functional Link)** Neural Network forms **Level 3** (the final detection tier) of the InsiEDR pipeline. 

While the Isolation Forest (Level 1) identifies point anomalies and XGBoost (Level 2) identifies scenario categories on individual days, malicious insider threats typically develop **gradually over time**. Insiders may test system boundaries, stage files over multiple days, and change their daily routines before executing an exfiltration.

The RedRVFL architecture models the **temporal sequence dynamics of user risk over 7-day sliding windows**. It learns to predict what a user's risk *should* be on Day 7 based on Days 1–6. When an insider starts deviating from their established behavioral pattern, the model's prediction error spikes. This prediction error represents **Behavioral Drift**.

```
    Day 1     Day 2     Day 3     Day 4     Day 5     Day 6        Day 7 (Target)
   ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐        ┌──────────────┐
   │rvfl_1│  │rvfl_2│  │rvfl_3│  │rvfl_4│  │rvfl_5│  │rvfl_6│  ───▶  │ Actual rvfl_7 │
   └──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘        └──────┬───────┘
                              │                                             │
                              ▼                                             ▼
                 ┌───────────────────────────┐                       ┌──────────────┐
                 │ 5-Layer Stacked RedRVFL   │ ────────────────────▶ │Predicted rvfl│
                 │ (Frozen Random LSTM +     │                       └──────┬───────┘
                 │  Ridge Ensemble)          │                              │
                 └───────────────────────────┘                              │
                                                                            ▼
                                                                 ┌────────────────────┐
                                                                 │   Squared Error    │
                                                                 │   (Actual - Pred)² │
                                                                 │   = Sequence Drift │
                                                                 └──────────┬─────────┘
                                                                            │
                                                                            ▼
                                                                 ┌────────────────────┐
                                                                 │   User Score v2    │
                                                                 │   Aggregation      │
                                                                 └────────────────────┘
```

---

## 2. Input Data & Signal Fusion

### 2.1 Signal Fusion (`rvfl_risk`)
Before building temporal sequences, the pipeline fuses the unsupervised anomaly score from Level 1 with the supervised scenario classification confidence from Level 2 into a single unified metric called `rvfl_risk`:

$$\text{scenario\_risk}_t = \max\Big(P_{\text{email}}(t), P_{\text{sabotage}}(t), P_{\text{usb}}(t), P_{\text{flight}}(t), P_{\text{cloud}}(t)\Big)$$

$$\text{rvfl\_risk}_t = 0.3 \cdot \text{overall\_risk}_t + 0.7 \cdot \text{scenario\_risk}_t$$

- **30% Weight (`overall_risk`)**: Anchors the score to general behavioral anomaly intensity.
- **70% Weight (`scenario_risk`)**: Amplifies high-confidence malicious scenario classifications.

### 2.2 7-Day Sliding Window Sequences
For each user independently (sorted chronologically by date), sliding window sequences are constructed using `create_sequences()`:
- **Sequence Length**: $W = 7$ days
- **Input Tensor Shape**: $(N, 7, 1)$ where $N$ is the number of valid sequences.
- **Target Value**: $y \in \mathbb{R}^N$, representing the `rvfl_risk` value on the 7th day of the window.

### 2.3 Feature & Target Normalization
Two independent `MinMaxScaler` instances are fitted strictly on the **training set sequences** to prevent scale skewing:
```python
feature_scaler = MinMaxScaler()
feature_scaler.fit(X_train_raw.reshape(-1, 1))

target_scaler = MinMaxScaler()
target_scaler.fit(y_train_raw)
```

---

## 3. RedRVFL Architecture & Mechanics

### 3.1 Why Random LSTM + Closed-Form Ridge?
Traditional Recurrent Neural Networks (like standard LSTMs or GRUs) trained via Backpropagation Through Time (BPTT) are prone to:
- Catastrophic forgetting
- Vanishing/exploding gradients
- High computational training time and overfitting on small insider sample sizes

The **Reduced Random Vector Functional Link (RedRVFL)** overcomes these issues by using **randomly initialized, permanently frozen recurrent feature extractors**, combined with **direct closed-form Ridge Regression solvers**:
1. Zero gradient-based backpropagation is performed.
2. High-dimensional nonlinear temporal projections are generated deterministically.
3. Training requires only solving a regularized linear system ($D^T D + \alpha I$), which completes in milliseconds and guarantees the global mathematical optimum.

---

### 3.2 Layer-by-Layer Architecture Details

The InsiEDR RedRVFL network (`RedRVFLOrchestrator`) consists of **5 stacked layers** (`num_layers=5`, `hidden_size=128`):

```
 Input X (batch, 7, 1)
   │
   ├───▶ Layer 1: RandomLSTM_1 ──────────▶ hidden_1 (batch, 128) ───▶ D_1 = [hidden_1, flat(X)] ───▶ Ridge_1
   │                                             │
   │                                             ▼
   ├───▶ Layer 2: RandomLSTM_2([X, hidden_1]) ──▶ hidden_2 (batch, 128) ───▶ D_2 = [hidden_2, flat(X)] ───▶ Ridge_2
   │                                             │
   │                                             ▼
   ├───▶ Layer 3: RandomLSTM_3([X, hidden_2]) ──▶ hidden_3 (batch, 128) ───▶ D_3 = [hidden_3, flat(X)] ───▶ Ridge_3
   │                                             │
   │                                             ▼
   ├───▶ Layer 4: RandomLSTM_4([X, hidden_3]) ──▶ hidden_4 (batch, 128) ───▶ D_4 = [hidden_4, flat(X)] ───▶ Ridge_4
   │                                             │
   │                                             ▼
   └───▶ Layer 5: RandomLSTM_5([X, hidden_4]) ──▶ hidden_5 (batch, 128) ───▶ D_5 = [hidden_5, flat(X)] ───▶ Ridge_5
                                                                                                          │
                                                                                                          ▼
                                                                                   Final Prediction: Median(ŷ_1..ŷ_5)
```

#### Layer 1:
- Input: $X \in \mathbb{R}^{B \times 7 \times 1}$
- Process: Passes through `RandomLSTM(input_size=1, hidden_size=128)` with frozen parameters.
- Hidden Representation: $h_1 \in \mathbb{R}^{B \times 128}$ (last timestep hidden state).
- Feature Matrix $D_1$: Concatenates hidden representation with flattened raw input:
  $$D_1 = [h_1 \,\|\, \text{flatten}(X)] \in \mathbb{R}^{B \times (128 + 7)}$$
- Model 1: Fits closed-form Ridge regression:
  $$W_1 = (D_1^T D_1 + \alpha I)^{-1} D_1^T y_{\text{train}}$$

#### Deeper Layers ($l = 2, 3, 4, 5$):
- Input: Constructs layer input by repeating the previous hidden state $h_{l-1}$ across all 7 time steps and concatenating it with $X$:
  $$X_l = [X \,\|\, \text{repeat}(h_{l-1}, 7)] \in \mathbb{R}^{B \times 7 \times (1 + 128)}$$
- Process: Passes through `RandomLSTM(input_size=129, hidden_size=128)` (each with a unique random seed).
- Feature Matrix $D_l$:
  $$D_l = [h_l \,\|\, \text{flatten}(X)] \in \mathbb{R}^{B \times 135}$$
- Model $l$: Fits Ridge regression $W_l$ on $D_l$.

### 3.3 Ensemble Prediction
During inference, each Ridge model produces a prediction $\hat{y}_l = D_l W_l$. The final predicted risk is computed as the **robust median** across all 5 layers:
$$\hat{y} = \text{median}\big(\hat{y}_1, \hat{y}_2, \hat{y}_3, \hat{y}_4, \hat{y}_5\big)$$

### 3.4 Model Hyperparameters

| Hyperparameter | Value | Description |
|---|---|---|
| `input_features` | `1` | Daily fused `rvfl_risk` value. |
| `sequence_length` | `7` | 7 consecutive calendar days per sequence window. |
| `hidden_size` | `128` | Number of hidden units per RandomLSTM layer. |
| `num_layers` | `5` | Total number of stacked recurrent projection layers. |
| `ridge_alpha` | `0.01` | L2 weight penalty regularization parameter. |
| `ridge_solver` | `lsqr` | Least squares solver for numerical efficiency. |

---

## 4. Sequence Drift & User-Level Threat Scoring

### 4.1 Daily Sequence Error
For every 7-day sequence across all users, the squared prediction error is computed:
$$\text{error}_i = \big(y_i - \hat{y}_i\big)^2$$
- **Normal Users**: Follow consistent behavioral trends $\implies$ the model accurately predicts Day 7 $\implies$ $\text{error} \approx 0.0$.
- **Insiders**: Experience sudden changes in file access, USB usage, or off-hours logon $\implies$ the model fails to predict Day 7 $\implies$ large $\text{error}$ spike.

### 4.2 Score v2 Aggregation Formula
Individual daily sequence errors for a user $u$ are aggregated into a single holistic threat score:

$$\text{Score\_v2}(u) = \text{max\_error}(u) \times \text{mean\_error}(u) \times \sqrt{N_u}$$

| Component | Technical Role |
|---|---|
| $\text{max\_error}(u)$ | Captures the single most extreme behavioral anomaly spike observed for user $u$. |
| $\text{mean\_error}(u)$ | Measures sustained, persistent malicious behavior over the entire monitoring period. |
| $\sqrt{N_u}$ | Statistical sample size scaling factor ($N_u$ = number of active sequences for user $u$). Prevents short-tenured false alarms while rewarding sustained observational confidence. |

---

## 5. Output of the RedRVFL Stage

### 5.1 Ranked Top Users (`top_users_shap.csv`)
All users in the organization are sorted in descending order of `Score_v2`. The highest scoring users are presented to SOC analysts.

### 5.2 Top-K Review Queue Evaluation (Test Set Results)
Evaluating on the 200 held-out test users (containing 10 actual insider threat actors across all 5 threat classes):

```
================================================================================
FINAL REDRVFL TOP-K REVIEW QUEUE (TEST SPLIT - 200 USERS)
================================================================================
Top-5    | Recall:  50.00% ( 5/10) | Precision: 100.00% ( 5/5)
          -> Insiders Found:
             U0430 (Score: 0.1888, Class: cloud_exfil)
             U0349 (Score: 0.1887, Class: sabotage)
             U0891 (Score: 0.1683, Class: sabotage)
             U0221 (Score: 0.1653, Class: flight_risk)
             U0719 (Score: 0.1545, Class: cloud_exfil)

Top-10   | Recall: 100.00% (10/10) | Precision: 100.00% (10/10)
          -> Insiders Found:
             U0430 (Score: 0.1888, Class: cloud_exfil)
             U0349 (Score: 0.1887, Class: sabotage)
             U0891 (Score: 0.1683, Class: sabotage)
             U0221 (Score: 0.1653, Class: flight_risk)
             U0719 (Score: 0.1545, Class: cloud_exfil)
             U0028 (Score: 0.1302, Class: usb_exfil)
             U0282 (Score: 0.1289, Class: flight_risk)
             U0604 (Score: 0.1116, Class: email_exfil)
             U0143 (Score: 0.1086, Class: email_exfil)
             U0229 (Score: 0.0940, Class: usb_exfil)
================================================================================
```

### 5.3 Generated Artifacts
- **Model File**: `final_model/output/rvfl_model.pkl` (contains all 5 RandomLSTM PyTorch layers)
- **Ridge Ensemble**: `final_model/output/rvfl_ridge_models.pkl` (contains 5 fitted Ridge estimators)
- **Scalers**: `final_model/output/feature_scaler.pkl` and `final_model/output/target_scaler.pkl`
- **Ranked User Output**: `final_model/output/top_users_shap.csv`
- **Confusion Matrix & Metrics**: `final_model/confusion_matrices/redrvfl/` (`redrvfl_user_confusion_matrix.csv`, `redrvfl_top_k_progression.csv`, `redrvfl_evaluation_summary.txt`)
