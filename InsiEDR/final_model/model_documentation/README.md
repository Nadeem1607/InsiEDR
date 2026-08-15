# Model Documentation

This folder contains documentation for each of the three models used in the InsiEDR insider threat detection pipeline.

---

## Pipeline Structure

The pipeline runs three models in sequence. Each model builds on the output of the previous one:

- **Level 1 — Isolation Forest**: Detects anomalous daily behavior across four activity domains (Logon, File, Device, HTTP) for every user.
- **Level 2 — XGBoost Classifier**: Takes those anomaly scores and classifies which specific insider threat scenario the user's behavior most closely matches.
- **Level 3 — RedRVFL Neural Network**: Analyzes how a user's combined risk score changes over time and identifies users whose behavior is drifting away from their own historical patterns.

---

## Documentation Files

| File | Model | Description |
|------|-------|-------------|
| [isolation_forest.md](isolation_forest.md) | Isolation Forest | Unsupervised anomaly detection across activity domains |
| [xgboost_classifier.md](xgboost_classifier.md) | XGBoost Classifier | Multiclass threat scenario classification |
| [redrvfl_neural_network.md](redrvfl_neural_network.md) | RedRVFL Neural Network | Temporal behavioral drift detection |

---

## How to Read Each Document

Each document is structured into three sections:

1. **Input Data Fed into the Model** — What raw features or scores the model receives.
2. **How the Model Works** — The steps the model takes to process the input.
3. **Output of the Model** — The scores, labels, or rankings the model produces.
