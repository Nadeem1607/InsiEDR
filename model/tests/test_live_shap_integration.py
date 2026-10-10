"""Real-artifact parity and contracts for the integrated model, not accuracy claims."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))
from src.server.inference import InferenceEngine, get_engine
from server.detectors.advanced_pipeline_detector import AdvancedPipelineDetector


class LiveIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = ROOT / "artifacts/shap_v1"
        if not cls.bundle.exists():
            raise unittest.SkipTest("Train/export the integration bundle first.")
        cls.engine = get_engine(cls.bundle)
        cls.raw = pd.read_csv(ROOT / "latest_data/raw_features.csv")
        cls.output = Path(os.environ["INSIEDR_PARITY_OUTPUT"])
        cls.enriched = pd.read_csv(cls.output / "scenario_training_dataset_with_xgb_shap.csv")
        cls.errors = pd.read_csv(cls.output / "explanations/daily_prediction_errors.csv")
        cls.ranked = pd.read_csv(cls.output / "top_users_shap.csv")
        cls.users = cls.ranked.user.iloc[[0, 20, -1]].tolist()

    def payload(self, user=None, count=None):
        user = user or self.users[0]
        rows = self.raw[self.raw.user == user].sort_values("date")
        if count is not None:
            rows = rows.head(count)
        return {"payload_id": "test", "username": user, "hostname": "synthetic-test-host",
                "daily_sequence": [{"date": row.date, "features": {
                    name: getattr(row, name) for name in self.engine.feature_columns}}
                    for row in rows.itertuples()]}

    def test_daily_features_and_probabilities_match_batch(self):
        for user in self.users:
            frame = self.engine._enrich(self.payload(user)["daily_sequence"])
            expected = self.enriched[self.enriched.user == user].sort_values("date")
            np.testing.assert_allclose(frame[self.engine.scenario_features],
                                       expected[self.engine.scenario_features], rtol=1e-7, atol=1e-9)
            probabilities = self.engine._probabilities(frame)
            columns = [f"rf_{name}_prob" for name in self.engine.scenario_names]
            np.testing.assert_allclose(probabilities, expected[columns], rtol=1e-6, atol=1e-7)

    def test_score_and_daily_errors_match_batch(self):
        for user in self.users:
            result = self.engine.predict_user_risk(self.payload(user), explain=False)
            expected = self.errors[self.errors.user == user].sort_values("date")
            np.testing.assert_allclose([day["error"] for day in result["detectors"]["red_rvfl"]["daily_errors"]],
                                       expected.error, rtol=3e-4, atol=2e-7)
            score = float(self.ranked.loc[self.ranked.user == user, "score_v2"].iloc[0])
            np.testing.assert_allclose(result["score_v2"], score, rtol=3e-4, atol=1e-10)

    def test_shap_is_signed_and_reconstructs_selected_margins(self):
        result = self.engine.predict_user_risk(self.payload())
        evidence = result["explanations"]
        self.assertTrue(evidence["available"], evidence)
        self.assertFalse(evidence["explains_final_score_v2"])
        for day in evidence["key_dates"]:
            for explanation in day["xgboost_explanations"]:
                contributions = explanation["all_features"]
                self.assertEqual(len(contributions), 40)
                self.assertAlmostEqual(explanation["base_raw_margin"] + sum(
                    item["shap_raw_margin"] for item in contributions), explanation["output_raw_margin"], places=3)
                self.assertTrue(all(item["shap_raw_margin"] > 0 for item in explanation["positive_features"]))
                self.assertTrue(all(item["shap_raw_margin"] < 0 for item in explanation["negative_features"]))
        with_shap = result["score_v2"]
        self.assertEqual(with_shap, self.engine.predict_user_risk(self.payload(), explain=False)["score_v2"])

    def test_warmup_has_no_fabricated_sequence_score(self):
        result = self.engine.predict_user_risk(self.payload(count=7))
        self.assertIsNone(result["score_v2"])
        self.assertEqual(result["mode"], "if_xgb_warmup")
        self.assertTrue(result["explanations"]["available"])

    def test_enriched_compatibility_api_matches_raw_inference(self):
        payload = self.payload(count=12)
        frame = self.engine._enrich(payload["daily_sequence"])
        probabilities = self.engine._probabilities(frame)
        enriched = [{"date": row["date"].isoformat(), "overall_risk": float(row.overall_risk),
                     **{f"rf_{name}_prob": float(probabilities[index, i])
                        for i, name in enumerate(self.engine.scenario_names)}}
                    for index, row in frame.iterrows()]
        compatible = self.engine.predict_behavioral_risk({**payload, "daily_sequence": enriched})
        raw = self.engine.predict_user_risk(payload, explain=False)
        self.assertEqual(compatible["score_v2"], raw["score_v2"])

    def test_shap_failure_does_not_change_detection(self):
        original = self.engine.predict_user_risk(self.payload(), explain=False)
        with patch.object(self.engine, "_explain_dates", side_effect=RuntimeError("test failure")):
            explained = self.engine.predict_user_risk(self.payload())
        self.assertEqual(original["score_v2"], explained["score_v2"])
        self.assertFalse(explained["explanations"]["available"])

    def test_duplicate_dates_rejected(self):
        payload = self.payload(count=8)
        payload["daily_sequence"][1]["date"] = payload["daily_sequence"][0]["date"]
        with self.assertRaisesRegex(ValueError, "unique"):
            self.engine.predict_user_risk(payload)

    def test_nonfinite_raw_values_rejected(self):
        payload = self.payload(count=8)
        payload["daily_sequence"][0]["features"][self.engine.feature_columns[0]] = float("inf")
        with self.assertRaisesRegex(ValueError, "Nonfinite"):
            self.engine.predict_user_risk(payload)

    def test_untrusted_derived_fields_recomputed(self):
        payload = self.payload(count=8)
        expected = self.engine.predict_user_risk(payload, explain=False)
        for day in payload["daily_sequence"]:
            day["features"].update({"raw_overall_risk": 999, "overall_risk": 999})
        self.assertEqual(expected["score_v2"], self.engine.predict_user_risk(payload, explain=False)["score_v2"])

    def test_bundle_version_mismatch_rejected(self):
        with patch("src.server.inference.version", return_value="wrong"):
            with self.assertRaisesRegex(ValueError, "Bundle requires"):
                InferenceEngine(self.bundle)

    def test_bundle_checksum_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = json.loads((self.bundle / "pipeline_config.json").read_text())
            metadata["sha256"] = {"tampered.pkl": "wrong"}
            Path(directory, "pipeline_config.json").write_text(json.dumps(metadata))
            Path(directory, "tampered.pkl").write_text("test")
            with self.assertRaisesRegex(ValueError, "checksum"):
                InferenceEngine(directory)

    def test_adapter_uses_hostname_and_does_not_duplicate_today(self):
        detector = AdvancedPipelineDetector.__new__(AdvancedPipelineDetector)
        detector._engine = self.engine
        payload = self.payload(count=8)
        rows = payload["daily_sequence"]
        class Storage:
            def list_daily_feature_vectors(self, **kwargs):
                self.query = kwargs
                return rows
        storage = Storage()
        sequence = detector._build_daily_sequence("synthetic", rows[-1]["features"], storage,
                                                 "correct-host", rows[-1]["date"] + "T12:00:00Z")
        self.assertEqual(storage.query["hostname"], "correct-host")
        self.assertEqual(len(sequence), 8)
        self.assertEqual(len({day["date"] for day in sequence}), 8)


if __name__ == "__main__":
    unittest.main()
