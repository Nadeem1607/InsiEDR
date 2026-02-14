# ml_integration_simple.py
"""
Simple ML Model Integration for EDR System
Uses Random Forest / Isolation Forest instead of LSTM
Much better accuracy and easier to deploy!
"""

import numpy as np
import json
from datetime import datetime
import joblib
import pickle
import os

class ThreatDetector:
    """Simple threat detector using Random Forest or Isolation Forest."""
    
    def __init__(
        self,
        model_path="model_available_features.pkl",
        scaler_path="scaler_available.pkl",
        feature_names_path="feature_names_available.pkl"
    ):
        """Load model and scaler."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        # Load model
        self.model = joblib.load(model_path)
        self.model_type = 'random_forest' if 'RandomForest' in str(type(self.model)) else 'isolation_forest'
        print(f"[+] Model loaded: {self.model_type}")
        
        # Load scaler
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print(f"[+] Scaler loaded")
        else:
            print(f"[-] WARNING: Scaler not found, predictions may be inaccurate!")
            self.scaler = None
        
        # Load feature names
        if os.path.exists(feature_names_path):
            with open(feature_names_path, 'rb') as f:
                self.feature_columns = pickle.load(f)
        else:
            # Default features from training (available features model)
            self.feature_columns = [
                'usb_count', 'file_count', 'afterhour_activity', 'afterhour_files',
                'workhour_activity', 'http_count', 'logon_count'
            ]
        print(f"[+] Using {len(self.feature_columns)} features")
    
    def extract_features(self, payload):
        """
        Extract features from agent payload that match training data.
        
        Maps real-time telemetry to the features the model expects.
        """
        # Current hour to detect after-hours activity
        try:
            hour = datetime.now().hour
            is_afterhours = hour < 8 or hour > 18
        except:
            is_afterhours = False
        
        # Extract from payload
        session = payload.get('session', {})
        file_act = payload.get('file_activity', {})
        network = payload.get('network_activity', {})
        email = payload.get('email_activity', {})
        usb_devices = payload.get('usb_devices', [])
        
        # Map to training feature names
        features = {
            'logon_count': 1,  # Currently logged in
            'usb_count': len(usb_devices),
            'file_count': len(file_act.get('risk_files_surface', [])),
            'email_count': email.get('sent_count', 0) + email.get('recv_count', 0),
            'http_count': network.get('active_connections', 0),
            'afterhour_activity': 1 if is_afterhours else 0,
            'afterhour_files': len(file_act.get('risk_files_surface', [])) if is_afterhours else 0,
            'afterhour_emails': email.get('sent_count', 0) if is_afterhours else 0,
            'workhour_activity': 0 if is_afterhours else 1,
            'usb_duration_avg': len(usb_devices) * 300  # Assume 5min avg per device
        }
        
        # Return as array in correct order
        feature_array = np.array([features.get(col, 0) for col in self.feature_columns])
        return feature_array
    
    def predict_threat(self, payload):
        """
        Predict threat level from agent payload.
        
        Returns:
            dict with prediction results
        """
        try:
            # Extract features
            features = self.extract_features(payload)
            
            # Scale features
            if self.scaler:
                features_scaled = self.scaler.transform(features.reshape(1, -1))[0]
            else:
                features_scaled = features
            
            # Predict
            if self.model_type == 'random_forest':
                # Get probability of being an insider threat
                prediction = self.model.predict(features_scaled.reshape(1, -1))[0]
                try:
                    proba = self.model.predict_proba(features_scaled.reshape(1, -1))[0][1]
                except:
                    proba = float(prediction)
                
                is_anomaly = prediction == 1
                risk_score = proba * 100
                
            else:  # Isolation Forest
                # Returns -1 for anomalies, 1 for normal
                prediction = self.model.predict(features_scaled.reshape(1, -1))[0]
                is_anomaly = prediction == -1
                
                # Get anomaly score (more negative = more anomalous)
                score = self.model.score_samples(features_scaled.reshape(1, -1))[0]
                risk_score = min(100, max(0, (1 - score) * 50))
            
            # Categorize risk
            if risk_score < 30:
                risk_level = "Low"
            elif risk_score < 70:
                risk_level = "Medium"
            else:
                risk_level = "High"
            
            return {
                "is_anomaly": bool(is_anomaly),
                "risk_score": float(risk_score),
                "risk_level": risk_level,
                "model_type": self.model_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"[-] Prediction error: {e}")
            import traceback
            traceback.print_exc()
            return {
                "is_anomaly": False,
                "risk_score": 0.0,
                "risk_level": "Unknown",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Global detector instance
_detector = None

def get_detector(
    model_path="model_available_features.pkl",
    scaler_path="scaler_available.pkl",
    feature_names_path="feature_names_available.pkl"
):
    """Get or create the global detector instance."""
    global _detector
    if _detector is None:
        _detector = ThreatDetector(model_path, scaler_path, feature_names_path)
    return _detector

def analyze_payload(payload, model_path="model_available_features.pkl"):
    """Analyze a single payload and return prediction."""
    detector = get_detector(model_path)
    return detector.predict_threat(payload)
