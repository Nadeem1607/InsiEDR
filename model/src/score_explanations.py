"""Explain batch user rankings without changing scores or model predictions."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import shap
import xgboost as xgb


def decompose_scores(daily_errors, ranked_users):
    """Reconstruct the score and expose observation count, not anomaly-day count."""
    required = {"user", "date", "error"}
    if not required.issubset(daily_errors.columns):
        raise ValueError(f"Missing daily error columns: {required - set(daily_errors.columns)}")
    if daily_errors.duplicated(["user", "date"]).any():
        raise ValueError("Daily errors must have one row per user and target date.")
    if not np.isfinite(daily_errors["error"]).all() or (daily_errors["error"] < 0).any():
        raise ValueError("Prediction errors must be finite and nonnegative.")
    components = daily_errors.groupby("user")["error"].agg(
        max_error="max", mean_error="mean", sequence_count="count", total_error="sum"
    ).reset_index()
    components["history_multiplier"] = np.sqrt(components["sequence_count"])
    components["reconstructed_score_v2"] = (
        components["max_error"] * components["mean_error"] * components["history_multiplier"]
    )
    # Keep ground-truth labels out of explanation generation.
    components = ranked_users[["user", "score_v2"]].merge(
        components, on="user", how="left", validate="one_to_one"
    )
    if components.isna().any().any():
        raise ValueError("A ranked user has no sequence-error history.")
    if not np.allclose(
        components["score_v2"], components["reconstructed_score_v2"], rtol=1e-10, atol=1e-12
    ):
        raise ValueError("Explanation components do not reconstruct the ranking score.")
    peak = daily_errors.sort_values(
        ["user", "error", "date"], ascending=[True, False, True], kind="stable"
    ).drop_duplicates("user")[["user", "date"]].rename(columns={"date": "peak_error_date"})
    return components.merge(peak, on="user", validate="one_to_one")


def normalize_shap_values(values, row_count, feature_count, class_count):
    """Support SHAP versions returning either class lists or a 3D array."""
    if isinstance(values, list):
        values = np.stack(values, axis=-1)
    values = np.asarray(values)
    expected = (row_count, feature_count, class_count)
    if values.shape != expected:
        raise ValueError(f"Unexpected multiclass SHAP shape {values.shape}; expected {expected}.")
    if not np.isfinite(values).all():
        raise ValueError("SHAP returned nonfinite contributions.")
    return values


def check_shap_additivity(values, base_values, raw_margins):
    reconstructed = values.sum(axis=1) + base_values
    residual = float(np.max(np.abs(reconstructed - raw_margins)))
    if not np.allclose(reconstructed, raw_margins, rtol=1e-4, atol=2e-4):
        raise ValueError(f"SHAP contributions do not reconstruct XGBoost margins: {residual}.")
    return residual


def format_shap_findings(report, features_per_direction=3):
    """Render already-computed evidence; never recompute predictions or scores."""
    if not 1 <= features_per_direction <= 5:
        raise ValueError("Features per direction must be between one and five.")
    users = report["users"]
    dates = sum(len(user["key_dates"]) for user in users)
    lines = [
        "=" * 80,
        "EXPLICIT SHAP FINDINGS: WHAT FEATURES INFLUENCED THE MODEL",
        "=" * 80,
        f"Coverage: {len(users)} top test-queue users; {dates} highest-error user dates.",
        "SHAP explains XGBoost scenario raw margins, NOT the final score_v2.",
        "Positive SHAP supports the named class; negative SHAP opposes that class.",
        "These values are margin units, NOT probability points or proof of malicious intent.",
        "Probabilities use softmax across all class margins; one class cannot be read alone.",
        "Background: tree-path training statistics, including SMOTE samples.",
        "Normal/prior medians are comparison references, NOT the SHAP baseline.",
        "Dates are selected by sequence prediction error, not by SHAP magnitude.",
        "Only the strongest features per direction are printed; the CSV contains all contributions.",
        "Scores and predictions are unchanged by this reporting layer.",
        "",
    ]
    for user in users:
        lines.extend([
            "-" * 80,
            f"USER {user['user']} | test-queue rank {user['test_queue_rank']} | "
            f"score_v2={user['score_v2']:.8g}",
            user["summary"],
        ])
        for day in user["key_dates"]:
            lines.extend([
                "",
                f"  KEY DATE {day['date'][:10]} | predicted scenario: {day['predicted_scenario']}",
                f"  Fused risk: observed={day['observed_fused_risk']:.8g}, "
                f"sequence-predicted={day['predicted_fused_risk']:.8g} "
                f"({day['deviation_direction'].replace('_', ' ')}).",
                f"  Scaled squared error={day['squared_error_scaled']:.8g}; "
                f"share of user's total squared error={day['share_of_total_squared_error']:.4%}.",
            ])
            for explanation in day["xgboost_explanations"]:
                role = ("highest-probability threat used for risk fusion (may NOT be the winning class)"
                        if explanation["role"] == "selected_threat_for_risk_fusion"
                        else "winning predicted class")
                lines.extend([
                    "",
                    f"    XGBOOST CLASS: {explanation['scenario']} | {role}",
                    f"    Model probability={explanation['probability']:.8g} "
                    f"({explanation['probability']:.4%}).",
                ])
                for key, heading, direction in [
                    ("positive_features", "SUPPORTING FEATURES (+ SHAP)", "increases"),
                    ("negative_features", "OPPOSING FEATURES (- SHAP)", "decreases"),
                ]:
                    lines.append(f"    {heading}:")
                    features = explanation[key][:features_per_direction]
                    if not features:
                        lines.append("      None: no contributions in this direction.")
                    for item in features:
                        lines.append(
                            f"      {item['feature']}: observed={item['observed_value']:.8g}; "
                            f"normal-training median={item['normal_training_median']:.8g}; "
                            f"prior-7-observation median={item['preceding_7_observations_median']:.8g}; "
                            f"SHAP={item['shap_raw_margin']:+.8g} -> {direction} "
                            f"the {explanation['scenario']} raw margin."
                        )
                reconstructed = explanation["base_raw_margin"] + explanation["sum_shap_raw_margin"]
                residual = abs(reconstructed - explanation["output_raw_margin"])
                lines.extend([
                    f"    MARGIN CHECK: baseline {explanation['base_raw_margin']:.8g} + "
                    f"sum of ALL feature SHAP values ({explanation['sum_shap_raw_margin']:+.8g}) "
                    f"= {reconstructed:.8g}; model margin={explanation['output_raw_margin']:.8g}; "
                    f"absolute residual={residual:.8g}.",
                ])
        lines.append("")
    lines.extend([
        "=" * 80,
        f"SHAP additivity check across all explained classes: "
        f"maximum absolute residual={report['shap_max_additivity_residual']:.8g}.",
        "Interpretation: features explain a trained model's decision, not causal intent.",
        "Correlated raw/derived features can share attribution; daily rows are not individual events.",
        "Full feature contributions: explanations/xgboost_local_shap.csv",
        "Structured evidence: explanations/user_explanations.json",
        "END OF EXPLICIT SHAP FINDINGS",
        "=" * 80,
    ])
    return "\n".join(lines) + "\n"


def export_score_explanations(
    output_dir, daily_errors, ranked_users, enriched_features, classifier,
    feature_columns, train_users, test_users, scenario_names, domain_weights,
    top_users=20, key_dates=3,
):
    """Explain test-queue users; local SHAP describes XGBoost, not score_v2."""
    if top_users < 1 or key_dates < 1:
        raise ValueError("Explanation user/date limits must be positive.")
    destination = Path(output_dir) / "explanations"
    destination.mkdir(parents=True, exist_ok=True)
    components = decompose_scores(daily_errors, ranked_users)
    components["evaluation_split"] = np.where(components["user"].isin(test_users), "test", "train")
    components.to_csv(destination / "score_decomposition.csv", index=False)
    daily_errors.to_csv(destination / "daily_prediction_errors.csv", index=False)

    frame = enriched_features.copy()
    frame["date"] = pd.to_datetime(frame["date"])
    if frame.duplicated(["user", "date"]).any():
        raise ValueError("Feature history must have one row per user and date.")
    selected_users = components[components["user"].isin(test_users)].head(top_users)
    selected_errors = []
    for user in selected_users["user"]:
        selected_errors.append(
            daily_errors[daily_errors["user"] == user]
            .sort_values(["error", "date"], ascending=[False, True], kind="stable")
            .head(key_dates)
        )
    if not selected_errors:
        raise ValueError("No test users are available for explanations.")
    selected = pd.concat(selected_errors, ignore_index=True)
    selected["date"] = pd.to_datetime(selected["date"])
    selected = selected.merge(frame, on=["user", "date"], how="left", validate="one_to_one")
    if selected[feature_columns].isna().all(axis=1).any():
        raise ValueError("A selected target date has no corresponding behavioral features.")
    X = selected[feature_columns].fillna(0)
    explainer = shap.TreeExplainer(
        classifier, model_output="raw", feature_perturbation="tree_path_dependent"
    )
    values = normalize_shap_values(
        explainer.shap_values(X), len(X), len(feature_columns), len(scenario_names)
    )
    base_values = np.asarray(explainer.expected_value)
    if base_values.shape != (len(scenario_names),):
        raise ValueError("Unexpected multiclass SHAP base values.")
    raw_margins = classifier.get_booster().predict(xgb.DMatrix(X), output_margin=True)
    shap_residual = check_shap_additivity(values, base_values, raw_margins)
    expected_classes = np.arange(len(scenario_names))
    if not np.array_equal(classifier.classes_, expected_classes):
        raise ValueError("Classifier class ordering differs from the scenario schema.")
    normal_train = frame[frame["user"].isin(train_users) & (frame["is_insider"] == 0)]
    if normal_train.empty:
        raise ValueError("Normal training users are needed for reference medians.")
    normal_medians = normal_train[feature_columns].fillna(0).median()
    probabilities = selected[[f"rf_{name}_prob" for name in scenario_names]].to_numpy()

    evidence_by_user = {}
    flat_attributions = []
    for row_index, row in selected.iterrows():
        user = row["user"]
        date = row["date"]
        prior = frame[(frame["user"] == user) & (frame["date"] < date)].sort_values("date").tail(7)
        if len(prior) != 7:
            raise ValueError("A target date does not have the seven observations used by RedRVFL.")
        prior_medians = prior[feature_columns].fillna(0).median()
        winning_class = int(np.argmax(probabilities[row_index]))
        threat_class = int(np.argmax(probabilities[row_index, 1:]) + 1)
        explanation_classes = list(dict.fromkeys([threat_class, winning_class]))
        scenario_explanations = []
        for class_index in explanation_classes:
            contributions = []
            for feature_index, feature_name in enumerate(feature_columns):
                contribution = {
                    "feature": feature_name,
                    "observed_value": float(X.iloc[row_index, feature_index]),
                    "normal_training_median": float(normal_medians[feature_name]),
                    "preceding_7_observations_median": float(prior_medians[feature_name]),
                    "shap_raw_margin": float(values[row_index, feature_index, class_index]),
                }
                contributions.append(contribution)
                flat_attributions.append({
                    "user": user, "date": date.isoformat(),
                    "scenario": scenario_names[class_index], **contribution,
                })
            contributions.sort(key=lambda item: abs(item["shap_raw_margin"]), reverse=True)
            scenario_explanations.append({
                "scenario": scenario_names[class_index],
                "role": "selected_threat_for_risk_fusion" if class_index == threat_class else "predicted_class",
                "probability": float(probabilities[row_index, class_index]),
                "base_raw_margin": float(base_values[class_index]),
                "output_raw_margin": float(raw_margins[row_index, class_index]),
                "sum_shap_raw_margin": float(values[row_index, :, class_index].sum()),
                "top_features": contributions[:5],
                "positive_features": [item for item in contributions if item["shap_raw_margin"] > 0][:5],
                "negative_features": [item for item in contributions if item["shap_raw_margin"] < 0][:5],
            })
        component = selected_users[selected_users["user"] == user].iloc[0]
        total_error = float(component["total_error"])
        event = {
            "date": date.isoformat(), "squared_error_scaled": float(row["error"]),
            "observed_risk_scaled": float(row["observed_risk_scaled"]),
            "predicted_risk_scaled": float(row["predicted_risk_scaled"]),
            "observed_fused_risk": float(row["observed_fused_risk"]),
            "predicted_fused_risk": float(row["predicted_fused_risk"]),
            "deviation_direction": "above_expected" if row["observed_risk_scaled"] > row["predicted_risk_scaled"]
                                   else "below_expected" if row["observed_risk_scaled"] < row["predicted_risk_scaled"]
                                   else "equal_to_expected",
            "share_of_total_squared_error": float(row["error"] / total_error) if total_error else 0.0,
            "contribution_to_mean_error": float(row["error"] / component["sequence_count"]),
            "domain_evidence": {
                domain: {
                    "risk": float(row[domain]), "weight": float(weight),
                    "weighted_raw_risk": float(row[domain] * weight),
                } for domain, weight in domain_weights.items()
            },
            "overall_risk": float(row["overall_risk"]),
            "selected_threat_probability": float(probabilities[row_index, threat_class]),
            "predicted_scenario": scenario_names[winning_class],
            "scenario_probabilities": {
                name: float(probabilities[row_index, index]) for index, name in enumerate(scenario_names)
            },
            "input_sequence": [
                {"date": item["date"].isoformat(), "fused_risk": float(item["rvfl_risk"])}
                for _, item in prior.iterrows()
            ],
            "xgboost_explanations": scenario_explanations,
        }
        evidence_by_user.setdefault(user, []).append(event)

    users = []
    for test_rank, (_, component) in enumerate(selected_users.iterrows(), start=1):
        user = component["user"]
        days = evidence_by_user[user]
        first = days[0]
        factor = {
            name: int(component[name]) if name == "sequence_count" else float(component[name])
            for name in ["max_error", "mean_error", "sequence_count", "history_multiplier", "reconstructed_score_v2"]
        }
        narrative = (
            f"{user} is ranked {test_rank} in the test-user queue. "
            f"score_v2={component['score_v2']:.6f} = peak squared error {factor['max_error']:.6f} "
            f"x mean squared error {factor['mean_error']:.6f} x sqrt({factor['sequence_count']}) "
            f"({factor['history_multiplier']:.4f}). "
            f"The largest error occurred on {first['date'][:10]}, when observed fused risk was "
            f"{first['observed_fused_risk']:.4f} versus predicted {first['predicted_fused_risk']:.4f} "
            f"({first['deviation_direction'].replace('_', ' ')}). "
            "Sequence count includes all evaluated observations; it is not the number of anomalous days. "
            "The ranking and scenario predictions are investigation signals, not proof of malicious intent."
        )
        users.append({
            "user": user, "test_queue_rank": test_rank, "score_v2": float(component["score_v2"]),
            "score_components": factor, "summary": narrative, "key_dates": days,
        })
    report = {
        "schema_version": "1.0", "score_type": "batch_user_ranking_score_v2",
        "score_formula": "max_error * mean_error * sqrt(sequence_count)",
        "error_definition": "Squared prediction residual in target_scaler space.",
        "sequence_definition": "Seven preceding observations predict the next observation; calendar days may be missing.",
        "decay": "No time decay is present in this branch's score_v2.",
        "shap_scope": "Local XGBoost class raw margins; not feature attribution to score_v2.",
        "shap_background": "Tree-path training statistics, including SMOTE training samples.",
        "reference_medians": "Normal original training rows and seven preceding user observations; not SHAP base values.",
        "key_date_selection": "Largest squared errors, with date as deterministic tie-breaker.",
        "requested_top_test_users": top_users, "requested_dates_per_user": key_dates,
        "explained_users": len(users), "explained_dates": len(selected),
        "shap_max_additivity_residual": shap_residual,
        "max_score_reconstruction_residual": float(np.max(np.abs(
            components["score_v2"] - components["reconstructed_score_v2"]
        ))),
        "limitations": [
            "SHAP contributions are in class-margin units, not probability points or portions of score_v2.",
            "Correlated raw and derived features can distribute attribution among related inputs.",
            "Daily aggregation cannot establish an event-level causal chain.",
            "A large error may be caused by risk falling below expectations as well as rising above them.",
            "The live endpoint currently uses a different risk-score formula.",
        ],
        "users": users,
    }
    with (destination / "user_explanations.json").open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
    pd.DataFrame(flat_attributions).to_csv(destination / "xgboost_local_shap.csv", index=False)
    lines = [
        "# User Ranking Explanations", "",
        "These explanations accompany the batch score_v2 ranking. They do not alter scores.", "",
        "Score: max squared error x mean squared error x square root of evaluated sequence count.",
        "Errors use target-scaled risk. Counts are observations, not anomalous days. No decay is applied.",
        "SHAP explains XGBoost class margins, not the final ranking score or causality.", "",
        f"Explained {len(users)} test users and {len(selected)} target dates.",
        f"Maximum SHAP reconstruction residual: {shap_residual:.8g}.", "",
    ]
    for user in users:
        lines.extend([f"## Test Rank {user['test_queue_rank']}: {user['user']}", "", user["summary"], ""])
        for day in user["key_dates"]:
            lines.extend([
                f"### {day['date'][:10]}", "",
                f"Observed fused risk **{day['observed_fused_risk']:.6f}**; predicted **{day['predicted_fused_risk']:.6f}**.",
                f"Scaled squared error: {day['squared_error_scaled']:.6f}; "
                f"share of total squared error: {day['share_of_total_squared_error']:.2%}.",
                f"Predicted scenario: **{day['predicted_scenario']}**. Selected threat probability for fusion: "
                f"{day['selected_threat_probability']:.6f}.", "",
                "| Domain | Risk | Fusion Weight | Weighted Raw Risk |",
                "| --- | ---: | ---: | ---: |",
            ])
            for domain, evidence in day["domain_evidence"].items():
                lines.append(f"| {domain} | {evidence['risk']:.6f} | {evidence['weight']:.6f} | {evidence['weighted_raw_risk']:.6f} |")
            for explanation in day["xgboost_explanations"]:
                lines.extend([
                    "", f"XGBoost explanation for **{explanation['scenario']}** "
                    f"(probability {explanation['probability']:.6f}). Positive SHAP increases this class's raw margin; negative decreases it.", "",
                    "| Feature | Observed | Normal Training Median | Prior 7 Median | SHAP Raw Margin |",
                    "| --- | ---: | ---: | ---: | ---: |",
                ])
                for item in explanation["top_features"]:
                    lines.append(
                        f"| {item['feature']} | {item['observed_value']:.6f} | {item['normal_training_median']:.6f} | "
                        f"{item['preceding_7_observations_median']:.6f} | {item['shap_raw_margin']:+.6f} |"
                    )
                lines.append(
                    f"\nMargin check: base {explanation['base_raw_margin']:.6f} + sum of all feature SHAP values "
                    f"{explanation['sum_shap_raw_margin']:.6f} = output {explanation['output_raw_margin']:.6f}."
                )
            lines.append("")
    (destination / "USER_EXPLANATIONS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved score decomposition for {len(components)} users and errors for {len(daily_errors)} target dates.")
    print(f"Saved explanations for {len(users)} test users / {len(selected)} dates to '{destination}'.")
    print(f"SHAP raw-margin additivity max residual: {shap_residual:.8g}")
    print("SHAP evidence explains XGBoost outputs; it does not claim attribution to score_v2.")
    findings = format_shap_findings(report)
    (destination / "SHAP_FINDINGS.txt").write_text(findings, encoding="utf-8")
    print(findings, end="")
    print(f"Explicit SHAP findings also saved to '{destination / 'SHAP_FINDINGS.txt'}'.")
    return report
