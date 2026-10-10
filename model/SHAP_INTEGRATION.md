# SHAP Model Integration

Local branch: `shap-model-integration`, based on `phase-2-updates` at `69aa7df`.
Nothing is pushed to GitHub. The separate standalone SHAP project is unchanged.

## Pipeline

```text
Cached daily features (or optional raw-log extraction)
  -> user split BEFORE Isolation Forest fitting
  -> four training-user-only Isolation Forests
  -> weighted risk / training-user maximum; cap at 1
  -> per-user risk delta and seven-observation rolling statistics
  -> training-only SMOTE -> six-class XGBoost
  -> fused risk = 0.3 * overall risk + 0.7 * largest threat probability
  -> seven-observation windows + training-fitted input/target scalers
  -> saved random RedRVFL layers + fitted ridge regressors
  -> scaled squared errors -> score_v2
  -> score decomposition and selected-date XGBoost SHAP

Complete exported bundle
  -> AdvancedPipelineDetector -> ModelBridge
  -> model_outputs.feature_contributions_json (existing JSONB column)
  -> /api/user-predictions/<username> -> dashboard user drill-down
```

Raw-log preprocessing runs only when cached feature inputs are unavailable.
Model-specific preparation runs inside `model/run_new_model.py`. The fixed
domain weights are inherited constants, not recalculated by the new SHAP layer.

## Changes

| Before | Integrated behavior |
| --- | --- |
| IF fit before user splitting | Split first; fit only training-user rows and score all rows |
| Backend selected old `latest_data/models` | Uses one bundle at `model/artifacts/shap_v1`, or `INSIEDR_MODEL_BUNDLE_DIR` |
| Mean domain score and hardcoded divisor | Same fixed weighted sum and exported training-only divisor as training |
| Missing `raw_overall_risk` in classifier input | Derives all nine risk/trend fields in the ordered 40-feature schema |
| Input scaler not applied; random layers reconstructed | Uses both fitted scalers and the serialized trained RedRVFL layers |
| Latest error multiplied by 1000 | Raw score_v2 over all supplied sequence errors, with explicit compatibility display adapter |
| IF-only cold start | IF/XGBoost warmup with SHAP; score_v2 stays unavailable until eight observations exist |
| Duplicate current-day history and agent ID used as hostname | UTC dates, actual hostname, one latest payload snapshot per date; current date replaced, not duplicated |
| Any latest two detector records | Latest record per relevant ML detector, with explicit `advanced_pipeline` output |
| No live signed SHAP | Selected-date evidence persists through JSONB/API and is displayed with supporting/opposing signs |

No new database schema/migration is needed. The rest of the application's risk
aggregation, heuristics, agents and raw-log extractors were not redesigned.
The optional separate FastAPI service in `model/inference/app.py` is not the
Flask app's live inference path and has not been integrated here.

## Numerical Contracts

```text
raw_overall_risk = sum(domain_weight * domain_IF_score)
overall_risk = min(raw_overall_risk / training_normalization_divisor, 1)
fused_risk = 0.3 * overall_risk + 0.7 * max(five threat-class probabilities)
error = (target_scaled_observed_fused_risk - predicted_scaled_fused_risk)^2
score_v2 = max(error) * mean(error) * sqrt(number_of_sequence_errors)
ML display adapter = min(score_v2 * 1000, 100)
```

The 0-100 adapter is for the existing app interface, NOT a probability or a
validated severity calibration. During warmup it instead displays IF risk times
100 and explicitly identifies that mode. Raw score_v2 remains separate. The
app's combined risk also incorporates other detectors/heuristics and smoothing;
it is NOT score_v2. Existing mean-error severity thresholds (0.02/0.05) are retained
for the ML detector and still require validation.

Live score_v2 covers up to 128 supplied observations by default
(`INSIEDR_MODEL_HISTORY_OBSERVATIONS`, bounded to 8-1000). The batch score covers
the entire provided user history. Scores agree when supplied histories agree;
different history horizons are not directly interchangeable. Seven observations
need not be seven consecutive calendar days.

SHAP explains selected XGBoost raw class margins:

```text
base class margin + sum(all 40 signed feature contributions) = output class margin
all class margins -> softmax -> scenario probabilities
```

It explains the largest threat probability used in fusion and the winning class
if different. At most three highest-error dates are selected; warmup explains
the latest observation. SHAP is not a complete attribution of score_v2, RedRVFL,
the risk aggregator or an employee's intent. Positive means supports this class;
negative means opposes this class. Values are margin units, not percentage points.
Tree-path background includes SMOTE samples. Normal/prior medians are comparison
references, not the SHAP baseline. A SHAP failure returns an explicit unavailable
status without changing valid model scores.

## Bundle and Training

Use Python 3.12 and `model/requirements-shap.txt`; artifacts enforce their exact
package versions and SHA-256 checksums at loading. Pickle files must come from a
trusted local training run. A manifest provides integrity consistency, not proof
of authenticity against a malicious bundle.

From repository root, with an activated compatible environment:

```powershell
python -B -u model/run_new_model.py --input-logs '<dataset directory>'
```

The dataset directory must contain `OUTPUT_LABELS/insider_labels.csv`.
Cached behavioral data is read from `model/latest_data/raw_features.csv`; no
private or additional dataset is committed. Default outputs are `model/output`,
`model/confusion_matrices`, and `model/artifacts/shap_v1`. `--run-dir` places these
outputs under another run directory; select its bundle with
`INSIEDR_MODEL_BUNDLE_DIR`, or copy the complete bundle, not individual artifacts.
The script also exports batch explanations unless `--skip-explanations` is used.

`pipeline_config.json` contains normalization, weights, class order, reference
medians, fit-boundary counts, dependency versions and artifact hashes.
Generated bundles are gitignored and must be exported/deployed separately. Docker
uses Python 3.12 and copies the model requirements before installing; Docker itself
was not built/tested during this local integration.

## Verification on This Machine

- Canonical updated training script completed successfully.
- Twenty-one model checks passed: fit boundary, batch/live features and class
  probabilities, sequence errors and score_v2, signed SHAP margin reconstruction,
  unchanged scores with SHAP disabled/failing, duplicate-date handling, warmup,
  derived-field replacement, artifact/version rejection and history handling.
- Batch parity was checked for three representative users, using identical full
  histories. Error tolerance: relative 3e-4 / absolute 2e-7; score relative 3e-4 /
  absolute 1e-10. Different batch sizes can produce small floating-point differences.
- Real PostgreSQL testing exercised daily history, ModelBridge inference, JSONB
  persistence, ML-specific prediction selection and HTTP retrieval.
- The synthetic demonstration has twelve observations/five sequence errors:
  score_v2 `0.0010537361617772264`, max SHAP additivity residual `3.34e-6`.
- Dashboard renders raw score/decomposition, key dates, signed attributions and
  all-feature comparison tables for `SYNTHETIC_SHAP_DEMO`.

Training/verification files are stored outside this repository at
`../phase-2-local-runtime/`: `shap_integration_training/run_log.txt`,
`shap_integration_tests.txt`, `shap_application_verification.json`.
The local database is separate (port 55432). The synthetic demo does not represent
a real employee or endpoint; no endpoint agent was started.

To rerun model tests, point parity checks at the output of the matching training:

```powershell
$env:INSIEDR_PARITY_OUTPUT = '<matching training run>/output'
python -m unittest discover -s model/tests -v
```

## Remaining Validation

This integration is not a production-readiness claim. Threshold/display
calibration, time-based evaluation, out-of-fold downstream training, sustained
high-risk behavior and monitoring are still open. The inherited batch top-k loop
uses test labels to select a cutoff; its adaptive/hardcoded summary numbers are
not an unbiased production-performance estimate. That loop was not redesigned
as part of this SHAP/fit-boundary integration.

Live stored payload snapshots are not automatically equivalent to CERT daily
aggregated feature rows. Real telemetry feature definitions, coverage, idle days
and operating-population drift still need validation. Missing raw fields are
zero-filled for model compatibility and are reported by the bridge; zero does
not prove that a measurement was observed.
