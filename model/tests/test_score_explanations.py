import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.score_explanations import (
    check_shap_additivity, decompose_scores, normalize_shap_values,
)


class ScoreExplanationTests(unittest.TestCase):
    def setUp(self):
        self.errors = pd.DataFrame({
            "user": ["A", "A", "A", "B"],
            "date": ["2024-01-08", "2024-01-09", "2024-01-10", "2024-01-08"],
            "error": [0.0, 0.25, 1.0, 0.0],
        })
        self.ranking = pd.DataFrame({
            "user": ["A", "B"], "score_v2": [(1.25 / 3) * np.sqrt(3), 0.0],
        })

    def test_reconstructs_score_and_counts_zero_error_observations(self):
        result = decompose_scores(self.errors, self.ranking).set_index("user")
        self.assertEqual(result.loc["A", "sequence_count"], 3)
        self.assertEqual(result.loc["A", "peak_error_date"], "2024-01-10")
        self.assertAlmostEqual(result.loc["A", "reconstructed_score_v2"], self.ranking.iloc[0]["score_v2"])
        self.assertEqual(result.loc["B", "reconstructed_score_v2"], 0.0)

    def test_rejects_score_mismatch(self):
        self.ranking.loc[0, "score_v2"] += 0.1
        with self.assertRaisesRegex(ValueError, "reconstruct"):
            decompose_scores(self.errors, self.ranking)

    def test_rejects_duplicate_target_dates(self):
        with self.assertRaisesRegex(ValueError, "one row"):
            decompose_scores(pd.concat([self.errors, self.errors.iloc[:1]]), self.ranking)

    def test_rejects_invalid_errors(self):
        for invalid in [-1.0, np.nan, np.inf]:
            with self.subTest(invalid=invalid):
                errors = self.errors.copy()
                errors.loc[0, "error"] = invalid
                with self.assertRaisesRegex(ValueError, "finite"):
                    decompose_scores(errors, self.ranking)

    def test_normalizes_old_and_new_multiclass_shap_outputs(self):
        old = [np.full((2, 3), index, dtype=float) for index in range(6)]
        new = np.stack(old, axis=-1)
        np.testing.assert_array_equal(normalize_shap_values(old, 2, 3, 6), new)
        np.testing.assert_array_equal(normalize_shap_values(new, 2, 3, 6), new)
        with self.assertRaisesRegex(ValueError, "shape"):
            normalize_shap_values(np.zeros((2, 6, 3)), 2, 3, 6)

    def test_verifies_margin_additivity_and_rejects_probability_units(self):
        values = np.ones((2, 3, 6)) * 0.5
        bases = np.arange(6, dtype=float)
        margins = values.sum(axis=1) + bases
        self.assertEqual(check_shap_additivity(values, bases, margins), 0.0)
        with self.assertRaisesRegex(ValueError, "margins"):
            check_shap_additivity(values, bases, np.ones((2, 6)) / 6)


if __name__ == "__main__":
    unittest.main()
