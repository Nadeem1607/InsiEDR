# Retrained pipeline: results and decisions

A new model has trained without overwriting either prior pipeline. The primary target is >80% **balanced accuracy**. Ordinary accuracy is also reported, because a model predicting normal every day already scores around 99% on these rare-attack populations. A high accuracy number alone does not establish useful detection.

## Selected model

- Training: 51,840 original/v2 training rows. No historical evaluation rows enter fitting. Tier 2: level_d3_cap5, two fixed-seed boosters, six probabilities, 40 ordered inputs.
- Four IF domain forests are calibrated on disjoint reserved normal training hosts. Only upper-tail percentile scores receive anomaly risk. This replaces the old high normal-risk floor.
- Fusion: `weighted15`. RedRVFL: seven daily inputs, three frozen 64-unit random-LSTM layers, Ridge alpha 1000.0, `upward` next-risk error. Only Ridge heads train.
- All candidates and the selection rule were recorded before inspecting this run’s heldout results. Alert thresholds optimize worst-cohort validation balanced accuracy with <=3% normal FPR in each validation population.
- Seed 63001 is additional validation, explicitly never a test. Seed 63002 was generated after freezing the selected models/thresholds. Both contain all seven attack families; supervised fitting still contains only the five known primitives plus normal.
- The old test/challenge/fresh sets were examined in prior work. The new seed is a prospective synthetic check, not independent real-world data; it shares the same attack mechanisms.

## Daily performance

| Population | Stage | Accuracy | Balanced accuracy | Attack recall | Precision | Normal FPR | PR-AUC |
|---|---|---:|---:|---:|---:|---:|---:|
| train_original | threat | 98.78% | 96.90% | 95.00% | 26.89% | 1.20% | 0.8514 |
| train_original | temporal | 99.03% | 97.03% | 95.00% | 34.55% | 0.95% | 0.7999 |
| train_augmented | threat | 98.81% | 96.02% | 93.17% | 46.63% | 1.13% | 0.9015 |
| train_augmented | temporal | 98.94% | 95.63% | 92.25% | 52.97% | 0.98% | 0.8874 |
| validation_original | threat | 97.93% | 84.80% | 71.43% | 25.32% | 1.84% | 0.5642 |
| validation_original | temporal | 98.18% | 84.92% | 71.43% | 28.17% | 1.59% | 0.4927 |
| validation_new | threat | 98.51% | 85.09% | 71.34% | 43.08% | 1.16% | 0.7126 |
| validation_new | temporal | 98.59% | 84.84% | 70.70% | 49.12% | 1.02% | 0.7098 |
| test | threat | 98.12% | 80.69% | 62.96% | 25.00% | 1.59% | 0.6121 |
| test | temporal | 98.36% | 80.81% | 62.96% | 28.33% | 1.34% | 0.6053 |
| challenge | threat | 98.02% | 85.58% | 72.86% | 31.87% | 1.70% | 0.6625 |
| challenge | temporal | 98.03% | 86.26% | 74.19% | 35.94% | 1.67% | 0.6421 |
| old_fresh | threat | 98.66% | 94.68% | 90.59% | 49.36% | 1.24% | 0.8835 |
| old_fresh | temporal | 98.84% | 94.20% | 89.41% | 56.93% | 1.02% | 0.8782 |
| prospective_holdout | threat | 98.28% | 86.71% | 74.84% | 39.40% | 1.43% | 0.7111 |
| prospective_holdout | temporal | 98.31% | 85.81% | 72.96% | 43.61% | 1.33% | 0.7077 |

Temporal metrics exclude targets without seven consecutive prior days. This is detection after observing the target day’s risk, not a promise to predict attack labels in advance. The >80% target refers to binary attack detection, not six-class scenario macro-F1.

## Comparison on identical historical data

| Population | Old Tier 2 balanced accuracy | New Tier 2 balanced accuracy | Old temporal balanced accuracy | New temporal balanced accuracy |
|---|---:|---:|---:|---:|
| test | 81.05% | 80.69% | 70.03% | 80.81% |
| challenge | 85.87% | 85.58% | 69.76% | 86.26% |

## Final error-based host ranking

The operational score uses the latest **15 eligible target days**. Ground truth and alert thresholds refer to that same interval. Full-period ranking files are retained without thresholds for historical triage; they are not directly comparable to last15 host accuracy.

| Population | Eligible hosts | Attack hosts in interval | Accuracy | Balanced accuracy | Recall | Precision | Normal-host FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| test | 216 | 9 | 95.37% | 76.33% | 55.56% | 45.45% | 2.90% |
| challenge | 216 | 13 | 95.83% | 86.98% | 76.92% | 62.50% | 2.96% |
| prospective_holdout | 216 | 18 | 97.22% | 88.38% | 77.78% | 87.50% | 1.01% |

## Generalization and remaining failures

- Original-training minus test: Tier 2 balanced-accuracy gap +16.21%; Tier 2 AP gap +0.2393; temporal balanced-accuracy gap +16.21%.
- Original-training minus challenge: Tier 2 balanced-accuracy gap +11.32%; Tier 2 AP gap +0.1890; temporal balanced-accuracy gap +10.76%.
- Original-training minus prospective_holdout: Tier 2 balanced-accuracy gap +10.19%; Tier 2 AP gap +0.1403; temporal balanced-accuracy gap +11.21%.

Prospective whole-host bootstrap 95% intervals (300 resamples):

- threat_balanced_accuracy: [0.8280, 0.9043].
- temporal_balanced_accuracy: [0.8221, 0.8935].
- threat_ap: [0.6189, 0.7826].
- temporal_ap: [0.6141, 0.7845].

Scenario outcomes remain in evaluation.json. Known-class identification accuracy is separate from binary detection. No labels or holdout examples were changed to achieve the target.

| Test scenario | Days | Tier 2 alert rate | Temporal alert rate | Trained class? |
|---|---:|---:|---:|---|
| BENIGN | 3213 | 1.6% | 1.3% | True |
| CLOUD_EXFILTRATION_PRECURSOR | 4 | 100.0% | 100.0% | True |
| CREDENTIAL_DUMP | 4 | 100.0% | 100.0% | True |
| DATA_HOARDING | 2 | 0.0% | 0.0% | True |
| HONEYTOKEN_TRIP | 4 | 0.0% | 0.0% | False |
| IT_SABOTAGE | 4 | 100.0% | 100.0% | True |
| KILL_CHAIN_APT | 3 | 0.0% | 0.0% | False |
| USB_EXFILTRATION_PRECURSOR | 6 | 83.3% | 83.3% | True |

## Target verdict

- test: Tier 2 >80% balanced accuracy **True**; temporal >80% **True**; last15 host alerts >80% **False**.
- challenge: Tier 2 >80% balanced accuracy **True**; temporal >80% **True**; last15 host alerts >80% **True**.
- prospective_holdout: Tier 2 >80% balanced accuracy **True**; temporal >80% **True**; last15 host alerts >80% **True**.

Passing a point-estimate target on one synthetic cohort cannot certify absence of overfitting or memorization. Check the uncertainty intervals, attack recall, precision and cohort gaps. No retuning was performed after prospective scores were read. Independently observed benign telemetry and independent attack mechanisms remain required for real deployment claims.

## Passed implementation checks

- Future perturbations cannot alter earlier model features or predictions. Shuffling rows preserves keyed predictions. Missing dates and host boundaries cannot form sequences. Duplicate host/day inputs are rejected.
- Label-free saved-model CLI inference matches prospective probabilities, forecasts, errors and decisions. Original datasets and frozen model checksums are unchanged. No exact training vectors occur in the new holdout.
- TreeSHAP is exact per booster and exported as mean signed class-margin contributions. They do not sum to the logit of the ensemble’s averaged probability. Explanations refer to Tier 2, not the final error score.

All decisions are in protocol.json, decisions.jsonl, tier2_candidates.json, temporal_candidates.json and frozen_selection.json. Predictions/rankings for every population and auditable input/export files are alongside this report.
