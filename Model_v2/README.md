# Improved architecture training, revision 2

This is a new run; neither the first trained daily pipeline nor the GitHub models are overwritten. The target is >80% **balanced accuracy**, with attack recall, precision, FPR, ordinary accuracy, and average precision all reported. With attack prevalence around 1%, ordinary accuracy alone is misleading.

## Decisions fixed before this run's evaluation

1. Keep the architecture flow: four domains of IF, ordered 40-column input to six-class XGBoost, seven consecutive daily fused risks, random-LSTM/Ridge RedRVFL, error-based ranking and exact local TreeSHAP. The classifier retains normal plus five trained primitive classes; honeytoken/kill-chain are evaluated as unseen attacks.
2. Train on the same 51,840 training rows. Do not add old validation, test, challenge, or old fresh-cohort examples to fitting. Fit forests on 80% of simulated normal training hosts and calibrate anomaly percentiles on the disjoint 20%. Model scores emphasize the upper tail rather than assigning ordinary behavior a .5 anomaly baseline. Domain definitions are documented in core.py and form a partition of all 40 raw daily features.
3. Compare six prespecified regularized multiclass candidates. Check one entirely held-out augmentation cohort on later training dates, the original validation partition, and one new validation seed. Rank candidates using the recorded cross-population AP/gap criterion. Refit the selected specification with two fixed seeds and average their six probability vectors. No dates, identities, labels, campaign IDs, or generator seeds enter estimator matrices. These weighted output scores have not undergone independent probability calibration.
4. Use new validation seed 63001 with all seven attack families and fresh host prefixes. It is explicitly development data, not a test. The cohort generator is the previous training generator with family scheduling broadened from five to seven **only for validation and prospective testing**. It does not add unseen-family examples to supervised training. All telemetry mechanisms remain shared synthetic mechanisms; this is not a new real-world population.
5. RedRVFL trains on clean eight-day windows of forward-cross-fitted upstream scores; histories cannot cross gaps, hosts, attacks or upstream model versions. Compare four documented fusion choices, three Ridge penalties, and absolute/upward forecasting error. Select on validation detection performance rather than only normal MAE. Frozen random LSTM layers and trainable Ridge heads retain the reference structure. Upward error, if selected, treats only unexpectedly increased risk as an alert signal; this is a logged deviation from the earlier absolute-error choice.
6. Thresholds maximize the minimum balanced accuracy across both validation populations with no more than 3% normal-day FPR in either. This trades some precision/false alarms for recall; the resulting precision is always reported. It cannot guarantee 80% performance on another population.
7. Keep max(error) × mean(error) × sqrt(count) ranking, but operational host alerts use exactly the latest 15 eligible daily errors per host. Fewer than 15 forecasts are ineligible. Full-period unthresholded scores are retained separately. Host ground truth for last15 scoring refers only to those 15 target dates, not attacks anywhere in a longer history.
8. Freeze serialized models, all selected settings, thresholds and protocol hashes before generating seed 63002. Score it once without tuning afterward. It includes all seven attack families and new host/campaign IDs. Original test/challenge/fresh results were already inspected in earlier work, so they remain retrospective comparisons.
9. Explain the selected two-booster ensemble with averaged exact per-booster TreeSHAP contributions. These sum to mean class margins, not to the logit of the averaged class probability. Select top 20 test hosts and three largest-error dates each. No dashboard is added.

## Reproduce / infer

```powershell
python Model_v2/train.py
python Model_v2/predict.py --features Model_v2/run/prospective_holdout_inputs/X.csv --metadata Model_v2/run/prospective_holdout_inputs/metadata.csv --output Model_v2/inference_check
python Model_v2/audit_report.py
```

Training refuses to overwrite a frozen model. Use a new experiment directory for future tuning. Prepend real contiguous daily history for inference; first seven days have no forecast and first three have no relative-context estimate. Host ranking needs 15 eligible forecast days. Raw timestamps remain only in the source; daily dates/hostnames are grouping metadata. Load only trusted locally produced joblib files.

## Evidence

`run/protocol.json`, `decisions.jsonl`, `tier2_candidates.json`, `temporal_candidates.json`, `frozen_selection.json`, `forward_upstream_scores.csv`, `checks.json`, `schema.json`, `evaluation.json` and the final report retain all candidates, decisions and failures. The input schema/domain/fusion changes instantiate details not specified by the original image; they are not a claim to reproduce an unspecified exact mathematical architecture.

Synthetic validation and small historical attack populations cannot certify freedom from overfitting, memorization or real-world distribution shift. A new synthetic seed tests stochastic variation within these mechanisms. Production claims require independently collected longitudinal telemetry and independently authored attack tests.
