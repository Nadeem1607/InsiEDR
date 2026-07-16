import os
import json
import warnings
import joblib
import numpy as np
import torch
from src.red_revfl_orchestrator import RedRVFLOrchestrator
from src.server.features.feature_schema import (
    LOGON_FEATURES,
    FILE_FEATURES,
    DEVICE_FEATURES,
    HTTP_FEATURES
)

class InferenceEngine:
    """
    Stateless inference engine for the Insider Threat Detection System.
    Loads persisted Isolation Forest and RedRVFL models, validates input sequences,
    scores them, and fuses the scores.
    """
    def __init__(self, models_dir=None):
        from src.run.config import get_all_configs

        config = get_all_configs()[0]

        self.if_weight = config["IF_weight"]
        self.xgb_weight = config["XGB_weight"]
        self.rvfl_orchestrator = None
        if models_dir is None:
            models_dir = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "models")
            )
        self.models_dir = models_dir
        self.domain_if = None
        self.feature_scaler = None
        self.ridge_models = None
        self.rvfl_metadata = None
        self.feature_columns = None
        self.scenario_model = None
        self.scenario_features = None   
        self._load_models()

    def _load_models(self):
        if_path = os.path.join(self.models_dir, "domain_isolation_forest.pkl")
        scaler_path = os.path.join(self.models_dir, "feature_scaler.pkl")
        ridge_path = os.path.join(self.models_dir, "ridge_models.pkl")
        metadata_path = os.path.join(self.models_dir, "rvfl_metadata.json")
        columns_path = os.path.join(self.models_dir, "feature_columns_IF.json")

        # Load domain isolation forest
        if not os.path.exists(if_path):
            raise FileNotFoundError(f"Persisted Isolation Forest model not found at {if_path}")
        self.domain_if = joblib.load(if_path)

        # Load feature scaler
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Persisted feature scaler not found at {scaler_path}")
        self.feature_scaler = joblib.load(scaler_path)

        # Load ridge models
        if not os.path.exists(ridge_path):
            raise FileNotFoundError(f"Persisted ridge models not found at {ridge_path}")
        self.ridge_models = joblib.load(ridge_path)

        if not os.path.exists(metadata_path):
            raise FileNotFoundError(
                f"Persisted RVFL metadata not found at {metadata_path}"
            )

        with open(metadata_path, "r") as f:
            self.rvfl_metadata = json.load(f)

        self.rvfl_orchestrator = (
            RedRVFLOrchestrator(

                input_features=
                    self.rvfl_metadata[
                        "input_features"
                    ],

                hidden_size=
                    self.rvfl_metadata[
                        "hidden_size"
                    ],

                num_layers=
                    self.rvfl_metadata[
                        "num_layers"
                    ]

            )
        )
        # Load feature columns
        if not os.path.exists(columns_path):
            raise FileNotFoundError(f"Persisted feature columns not found at {columns_path}")
        with open(columns_path, "r") as f:
            self.feature_columns = json.load(f)
        xgb_model_path = os.path.join(
            self.models_dir,
            "scenario_xgb.pkl"
        )

        xgb_features_path = os.path.join(
            self.models_dir,
            "scenario_xgb_features.json"
        )
        if not os.path.exists(xgb_model_path):
            raise FileNotFoundError(
                f"Scenario XGB model not found at {xgb_model_path}"
            )

        self.scenario_model = joblib.load(
            xgb_model_path
        )

        if not os.path.exists(
            xgb_features_path
        ):
            raise FileNotFoundError(
                f"Scenario feature list not found at {xgb_features_path}"
            )

        with open(
            xgb_features_path,
            "r"
        ) as f:

            self.scenario_features = json.load(
                f
            )

    def predict_current_risk(
        self,
        payload
    ):

        if "features" not in payload:
            raise ValueError(
                "Missing 'features'"
            )

        features = payload["features"]

        required_features = (

            set(LOGON_FEATURES)

            |

            set(FILE_FEATURES)

            |

            set(DEVICE_FEATURES)

            |

            set(HTTP_FEATURES)

        )

        missing = (

            required_features

            -

            set(features.keys())

        )

        if missing:
            raise ValueError(
                f"Missing features: {sorted(list(missing))}"
            )

        logon_cols = [
            c
            for c in LOGON_FEATURES
            if c in features
        ]

        file_cols = [
            c
            for c in FILE_FEATURES
            if c in features
        ]

        device_cols = [
            c
            for c in DEVICE_FEATURES
            if c in features
        ]

        http_cols = [
            c
            for c in HTTP_FEATURES
            if c in features
        ]

        logon_X = np.array(
            [[features[c] for c in logon_cols]],
            dtype=np.float32
        )

        file_X = np.array(
            [[features[c] for c in file_cols]],
            dtype=np.float32
        )

        device_X = np.array(
            [[features[c] for c in device_cols]],
            dtype=np.float32
        )

        http_X = np.array(
            [[features[c] for c in http_cols]],
            dtype=np.float32
        )

        scores = self.domain_if.score(
            logon_X,
            file_X,
            device_X,
            http_X
        )

        logon_score = float(
            scores["logon"][0]
        )

        file_score = float(
            scores["file"][0]
        )

        device_score = float(
            scores["device"][0]
        )

        http_score = float(
            scores["http"][0]
        )

        overall_score = (
            logon_score +
            file_score +
            device_score +
            http_score
        ) / 4.0

        if overall_score >= 0.80:
            risk_level = "HIGH"
        elif overall_score >= 0.50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {

            "detector":
                "isolation_forest",

            "overall_score":
                round(
                    overall_score,
                    6
                ),

            "risk_level":
                risk_level,

            "domain_scores": {

                "logon":
                    round(
                        logon_score,
                        6
                    ),

                "file":
                    round(
                        file_score,
                        6
                    ),

                "device":
                    round(
                        device_score,
                        6
                    ),

                "http":
                    round(
                        http_score,
                        6
                    )

            }

        }
    def predict_behavioral_risk(
            self,
            payload
    ):

        required_keys = [

            "payload_id",
            "username",
            "hostname",
            "daily_sequence"

        ]

        for key in required_keys:

            if key not in payload:

                raise ValueError(
                    f"Missing required payload key: '{key}'"
                )

        daily_sequence = payload[
            "daily_sequence"
        ]

        seq_len = self.rvfl_metadata[
            "sequence_length"
        ]

        if len(
            daily_sequence
        ) < seq_len + 1:

            raise ValueError(

                f"daily_sequence must contain at least "
                f"{seq_len + 1} days of history. "

                f"Provided: {len(daily_sequence)}"

            )

        target_sequence = (

            daily_sequence[
                -(seq_len + 1):
            ]

        )

        rvfl_values = []

        for day in target_sequence:

            overall_risk = float(
                day["overall_risk"]
            )

            scenario_risk = max(

                float(
                    day["rf_s1_prob"]
                ),

                float(
                    day["rf_s2_prob"]
                ),

                float(
                    day["rf_s3_prob"]
                )

            )

            rvfl_risk = (

                self.if_weight * overall_risk

                +

                self.xgb_weight * scenario_risk

            )

            rvfl_values.append(
                [rvfl_risk]
            )

        features_array = np.array(

            rvfl_values,

            dtype=np.float32

        )

        X_seq = features_array[
            :seq_len
        ]

        y_actual = features_array[
            seq_len:
        ]

        X_tensor = torch.tensor(

            X_seq,

            dtype=torch.float32

        ).unsqueeze(0)

        y_pred = (

            self.rvfl_orchestrator
            .predict(

                X_tensor,

                self.ridge_models

            )

        )

        rvfl_error = float(

            np.mean(

                np.square(

                    y_actual.reshape(-1)

                    -

                    np.asarray(
                        y_pred
                    ).reshape(-1)

                )

            )

        )

        if rvfl_error >= 0.05:

            behavioral_risk = "HIGH"

            recommended_action = (
                "Escalate for analyst review."
            )

        elif rvfl_error >= 0.02:

            behavioral_risk = "MEDIUM"

            recommended_action = (
                "Monitor user behavior closely."
            )

        else:

            behavioral_risk = "LOW"

            recommended_action = (
                "No action required."
            )

        latest_day = target_sequence[-1]

        latest_scenario = max(

            [
                ("s1", float(latest_day["rf_s1_prob"])),
                ("s2", float(latest_day["rf_s2_prob"])),
                ("s3", float(latest_day["rf_s3_prob"]))
            ],

            key=lambda x: x[1]

        )

        return {

            "payload_id":
                payload["payload_id"],

            "username":
                payload["username"],

            "hostname":
                payload["hostname"],

            "rvfl_error":
                round(
                    rvfl_error,
                    6
                ),

            "behavioral_risk":
                behavioral_risk,

            "predicted_scenario": {

                "scenario":
                    latest_scenario[0],

                "confidence":
                    round(
                        latest_scenario[1],
                        6
                    )

            },

            "sequence_length_received":
                len(
                    daily_sequence
                ),

            "sequence_length_expected":
                seq_len,

            "model_versions": {

                "rvfl_model":
                    "v1",

                "scenario_model":
                    "external"

            },

            "recommended_action":
                recommended_action

        }
    def predict_scenario(
            self,
            payload
    ):

        if "features" not in payload:

            raise ValueError(
                "Missing 'features'"
            )

        features = payload[
            "features"
        ]

        missing = (

            set(
                self.scenario_features
            )

            -

            set(
                features.keys()
            )

        )

        if missing:

            raise ValueError(

                f"Missing scenario features: "
                f"{sorted(list(missing))}"

            )

        X = np.array([

            [

                features[col]

                for col in
                self.scenario_features

            ]

        ])

        probabilities = (

            self.scenario_model
            .predict_proba(X)[0]

        )

        class_labels = (
            self.scenario_model.classes_
        )

        class_map = {

            0: "normal",
            1: "s1",
            2: "s2",
            3: "s3"

        }

        prob_dict = {}

        for idx, cls in enumerate(
            class_labels
        ):

            prob_dict[
                f"rf_{class_map[cls]}_prob"
            ] = float(
                probabilities[idx]
            )

        predicted_class = (

            class_labels[
                np.argmax(
                    probabilities
                )
            ]

        )

        return {

            "scenario":

                class_map[
                    predicted_class
                ],

            "confidence":

                float(
                    np.max(
                        probabilities
                    )
                ),

            **prob_dict

        }
_engine = None    
def get_engine():
    global _engine
    if _engine is None:
        _engine = InferenceEngine()
    return _engine

def predict_current_risk(
    payload: dict
) -> dict:

    return (
        get_engine()
        .predict_current_risk(
            payload
        )
    )


def predict_behavioral_risk(
    payload: dict
) -> dict:

    return (
        get_engine()
        .predict_behavioral_risk(
            payload
        )
    )

def predict_scenario(
    payload: dict
) -> dict:

    return (
        get_engine()
        .predict_scenario(
            payload
        )
    )
