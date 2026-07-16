import os
import sys
import joblib
import torch
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.linear_model import Ridge

# Ensure project root is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.red_revfl_orchestrator import RedRVFLOrchestrator
from src.run.feature_to_sequence import create_sequences

def train_and_evaluate_rvfl(enriched_csv_path, test_users_list, output_anomaly_csv, output_users_csv, models_dir):
    """
    Step 5: Loads XGBoost probability enriched dataset, builds sequence windows,
    scales features, trains RedRVFL via Ridge regression, computes prediction error,
    and aggregates anomaly statistics per user using score_v2.
    """
    print(f"Loading enriched dataset from '{enriched_csv_path}'...")
    df = pd.read_csv(enriched_csv_path)
    df["date"] = pd.to_datetime(df["date"])
    
    # 1. Calculate scenario risk and fused RVFL risk
    prob_cols = [
        "rf_email_exfil_prob",
        "rf_sabotage_prob",
        "rf_usb_exfil_prob",
        "rf_flight_risk_prob",
        "rf_cloud_exfil_prob"
    ]
    
    print("Computing fused RVFL risk signal...")
    df["scenario_risk"] = df[prob_cols].max(axis=1)
    df["rvfl_risk"] = 0.3 * df["overall_risk"] + 0.7 * df["scenario_risk"]
    
    # Save the risk signals in the dataframe for evaluation later
    # Keep only the columns we need for sequencing
    seq_df = df[["user", "date", "rvfl_risk"]].copy()
    
    # 2. Split users into train and test
    train_df = seq_df[~seq_df["user"].isin(test_users_list)].copy()
    test_df = seq_df[seq_df["user"].isin(test_users_list)].copy()
    
    print(f"RVFL Split: {train_df['user'].nunique()} Train Users, {test_df['user'].nunique()} Test Users")
    
    # 3. Build sequences (7-day window)
    print("Building sequences (length=7)...")
    X_train_raw, y_train_raw, metadata_train = create_sequences(train_df, ["rvfl_risk"], sequence_length=7)
    X_test_raw, y_test_raw, metadata_test = create_sequences(test_df, ["rvfl_risk"], sequence_length=7)
    X_all_raw, y_all_raw, metadata_all = create_sequences(seq_df, ["rvfl_risk"], sequence_length=7)
    
    print(f"Train Sequences: X_shape={X_train_raw.shape}, y_shape={y_train_raw.shape}")
    print(f"Test Sequences: X_shape={X_test_raw.shape}, y_shape={y_test_raw.shape}")
    print(f"All Sequences: X_shape={X_all_raw.shape}, y_shape={y_all_raw.shape}")
    
    # 4. Scale features
    print("Scaling features...")
    feature_scaler = MinMaxScaler()
    feature_scaler.fit(X_train_raw.reshape(-1, X_train_raw.shape[2]))
    
    X_train = feature_scaler.transform(X_train_raw.reshape(-1, X_train_raw.shape[2])).reshape(X_train_raw.shape)
    X_test = feature_scaler.transform(X_test_raw.reshape(-1, X_test_raw.shape[2])).reshape(X_test_raw.shape)
    X_all = feature_scaler.transform(X_all_raw.reshape(-1, X_all_raw.shape[2])).reshape(X_all_raw.shape)
    
    target_scaler = MinMaxScaler()
    target_scaler.fit(y_train_raw)
    
    y_train = target_scaler.transform(y_train_raw)
    y_test = target_scaler.transform(y_test_raw)
    y_all = target_scaler.transform(y_all_raw)
    
    # Save scalers
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(feature_scaler, os.path.join(models_dir, "feature_scaler.pkl"))
    joblib.dump(target_scaler, os.path.join(models_dir, "target_scaler.pkl"))
    
    # 5. Train RedRVFL
    print("Training RedRVFL Model (hidden_size=128, layers=5)...")
    model = RedRVFLOrchestrator(
        input_features=1,
        hidden_size=128,
        num_layers=5
    )
    
    X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
    feature_matrices = model.extract_features(X_train_tensor)
    
    ridge_models = []
    for D in feature_matrices:
        ridge = Ridge(alpha=0.01, solver="lsqr")
        ridge.fit(D, y_train)
        ridge_models.append(ridge)
        
    # Save models
    joblib.dump(model, os.path.join(models_dir, "rvfl_model.pkl"))
    joblib.dump(ridge_models, os.path.join(models_dir, "rvfl_ridge_models.pkl"))
    
    # 6. Predict on ALL sequences to get error timeline for every user
    print("Predicting and calculating drift errors on all users...")
    X_all_tensor = torch.tensor(X_all, dtype=torch.float32)
    y_pred = model.predict(X_all_tensor, ridge_models)
    
    # Compute MSE prediction error (avoiding 2D/1D broadcasting bug)
    errors = np.square(y_all.ravel() - y_pred.ravel())
    
    # Create daily anomaly error DataFrame
    anomaly_rows = []
    for err, meta in zip(errors, metadata_all):
        anomaly_rows.append({
            "user": meta["user"],
            "date": meta["target_date"],
            "error": float(err)
        })
        
    anomaly_df = pd.DataFrame(anomaly_rows)
    anomaly_df.to_csv(output_anomaly_csv, index=False)
    print(f"Saved daily anomaly drift errors to '{output_anomaly_csv}' (Shape: {anomaly_df.shape})")
    
    # 7. Aggregate per-user statistics using score_v2
    print("Aggregating per-user threat scores...")
    user_scores = anomaly_df.groupby("user").agg(
        max_error=("error", "max"),
        mean_error=("error", "mean"),
        anomaly_days=("error", "count")
    ).reset_index()
    
    # Compute score_v2 = max_error * mean_error * sqrt(anomaly_days)
    user_scores["score_v2"] = (
        user_scores["max_error"] * 
        user_scores["mean_error"] * 
        np.sqrt(user_scores["anomaly_days"])
    )
    
    # Rank users by score_v2 descending
    user_scores = user_scores.sort_values("score_v2", ascending=False).reset_index(drop=True)
    
    # Merge with original insider labels to easily review test set recall
    labels_df = df[["user", "is_insider", "threat_scenario"]].drop_duplicates()
    user_scores = user_scores.merge(labels_df, on="user", how="left")
    
    user_scores.to_csv(output_users_csv, index=False)
    print(f"Saved ranked users by score_v2 to '{output_users_csv}' (Shape: {user_scores.shape})")
    
    print("\nTop 10 Suspicious Users by score_v2:")
    print(user_scores.head(10)[["user", "score_v2", "is_insider", "threat_scenario"]])
    
    return user_scores

if __name__ == "__main__":
    enriched_csv = r"c:\Users\Guruchandar\Downloads\insiEDR project\InsiEDR\latest_data\scenario_training_dataset_with_xgb.csv"
    # Dummy test users for testing script in isolation
    dummy_test_users = ["U0001", "U0002"]
    out_anomaly = r"c:\Users\Guruchandar\Downloads\insiEDR project\InsiEDR\latest_data\all_anomaly_days.csv"
    out_users = r"c:\Users\Guruchandar\Downloads\insiEDR project\InsiEDR\latest_data\top_users.csv"
    models_dir = r"c:\Users\Guruchandar\Downloads\insiEDR project\InsiEDR\latest_data\models"
    train_and_evaluate_rvfl(enriched_csv, dummy_test_users, out_anomaly, out_users, models_dir)
