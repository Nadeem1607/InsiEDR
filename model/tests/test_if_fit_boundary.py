"""Regression checks for the Isolation Forest train/test fitting boundary."""
import ast
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import run_new_model as pipeline


class IsolationForestFitBoundaryTests(unittest.TestCase):
    def feature_frame(self):
        cols = (pipeline.LOGON_FEATURES + pipeline.FILE_FEATURES
                + pipeline.DEVICE_FEATURES + pipeline.HTTP_FEATURES)
        frame = pd.DataFrame({c: [1.0, 999.0, 2.0] for c in cols}, index=[7, 11, 19])
        frame["user"] = ["TRAIN_A", "TEST_ONLY", "TRAIN_B"]
        frame["date"] = pd.to_datetime(["2026-01-01"] * 3)
        frame.loc[7, cols[0]] = np.nan
        return frame

    def test_fit_excludes_test_rows_but_score_and_predict_include_them(self):
        frame = self.feature_frame()
        domains = ["logon", "file", "device", "http"]
        with patch.object(pipeline, "DomainIsolationForest") as constructor, \
                patch.object(pipeline.joblib, "dump"):
            forest = constructor.return_value
            forest.score.return_value = {domain: np.array([0.1, 0.9, 0.2]) for domain in domains}
            forest.predict.return_value = {domain: np.array([1, -1, 1]) for domain in domains}
            enriched, returned = pipeline.train_domain_isolation_forests(
                frame, "unused_test_output", ["TRAIN_A", "TRAIN_B"])
            self.assertIs(returned, forest)
            fit_inputs = forest.fit.call_args.args
            score_inputs = forest.score.call_args.args
            predict_inputs = forest.predict.call_args.args
            for domain_index, cols in enumerate([
                    pipeline.LOGON_FEATURES, pipeline.FILE_FEATURES,
                    pipeline.DEVICE_FEATURES, pipeline.HTTP_FEATURES]):
                expected = frame[frame.user.isin(["TRAIN_A", "TRAIN_B"])][cols].fillna(0).to_numpy()
                np.testing.assert_array_equal(fit_inputs[domain_index], expected)
                self.assertFalse(np.any(fit_inputs[domain_index] == 999.0))
                np.testing.assert_array_equal(score_inputs[domain_index], frame[cols].fillna(0).to_numpy())
                np.testing.assert_array_equal(predict_inputs[domain_index], score_inputs[domain_index])
            self.assertEqual(set(enriched.user), set(frame.user))
            self.assertEqual(enriched.loc[enriched.user == "TEST_ONLY", "http_if_anomaly"].iloc[0], 1)

    def test_empty_training_subset_is_rejected(self):
        with patch.object(pipeline, "DomainIsolationForest") as constructor:
            with self.assertRaisesRegex(ValueError, "training users"):
                pipeline.train_domain_isolation_forests(self.feature_frame(), "unused_test_output", ["ABSENT"])
            constructor.assert_not_called()

    def test_main_splits_users_before_fitting_forests(self):
        tree = ast.parse((ROOT / "run_new_model.py").read_text(encoding="utf-8"))
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        split = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "stratified_user_split"]
        fit = [node for node in ast.walk(main) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Name) and node.func.id == "train_domain_isolation_forests"]
        self.assertEqual(len(split), 1)
        self.assertEqual(len(fit), 1)
        self.assertLess(split[0].lineno, fit[0].lineno)
        self.assertEqual(fit[0].args[2].id, "train_users")


if __name__ == "__main__":
    unittest.main()
