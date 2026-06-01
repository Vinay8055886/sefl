import time
import math
import numpy as np
from sklearn.ensemble import IsolationForest
import threading

class MLAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.is_trained = False
        self.training_buffer = []
        self.retrain_threshold = 100
        self._lock = threading.Lock()

    def _extract_features(self, telemetry):
        # We assume telemetry provides these directly or we compute them here
        # Telemetry is the raw event or enhanced event
        # Actually, in app.py we will pass a dict with these features computed or raw
        # Let's expect the dict to have these keys, or default them
        return [
            float(telemetry.get('requests_per_minute', 0.0)),
            float(telemetry.get('endpoint_diversity', 1.0)),
            float(telemetry.get('sensitive_route_ratio', 0.0)),
            float(telemetry.get('avg_interval', 10.0)),
            float(telemetry.get('payload_entropy', 0.0)),
            float(telemetry.get('failed_auth_ratio', 0.0)),
            float(telemetry.get('probe_density', 0.0)),
            float(telemetry.get('header_rarity', 0.0))
        ]

    def predict(self, telemetry):
        features = self._extract_features(telemetry)
        
        with self._lock:
            self.training_buffer.append(features)
            
            # Retrain if threshold reached
            if len(self.training_buffer) >= self.retrain_threshold:
                X = np.array(self.training_buffer)
                self.model.fit(X)
                self.is_trained = True
                # Keep only recent data to adapt to concept drift
                if len(self.training_buffer) > 1000:
                    self.training_buffer = self.training_buffer[-1000:]
        
        if not self.is_trained:
            # Heuristic fallback before enough data is collected
            score = 0.0
            if features[2] > 0.5: score += 0.4
            if features[5] > 0.5: score += 0.4
            if features[6] > 10.0: score += 0.3
            prob = min(score, 1.0)
            label = "ANOMALY" if prob > 0.6 else "NORMAL"
            return {"anomaly_probability": prob, "anomaly_label": label}

        # Predict using Isolation Forest
        X_test = np.array([features])
        decision_score = self.model.decision_function(X_test)[0]
        # Scikit-learn IF: negative is anomaly, positive is normal.
        # Let's map it to probability [0, 1] where 1 is highly anomalous.
        prob = 1.0 / (1.0 + math.exp(decision_score * 5))
        label = "ANOMALY" if self.model.predict(X_test)[0] == -1 else "NORMAL"
        
        return {
            "anomaly_probability": prob,
            "anomaly_label": label
        }
