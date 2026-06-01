"""
risk_engine.py — Real-Time Risk Scoring Engine
================================================
Computes a continuous risk score for each IP/user based on behavioral
feature vectors from the BehaviorAnalyzer. Uses weighted multi-signal
fusion with exponential decay.

Risk Score Formula:
  RiskScore(t) = α×Freq + β×Fail + γ×Pattern + δ×Payload + ε×Session + ζ×Baseline
  
  With exponential decay applied to historical scores:
  DecayedScore = CurrentScore × e^(-λΔt) + NewScore × (1 - e^(-λΔt))

Risk Levels:
  0-30:   NORMAL
  31-60:  ELEVATED
  61-80:  SUSPICIOUS
  81-100: MALICIOUS
"""

import time
import math
from database import update_risk_score, get_risk_score, log_system_event

# ─── Weight Configuration ─────────────────────────────────────────────

WEIGHTS = {
    "frequency": 0.22,
    "failure": 0.28,
    "pattern": 0.20,
    "payload": 0.15,
    "session": 0.08,
    "baseline": 0.07,
}

# Exponential decay parameter (controls how fast old scores decay)
DECAY_LAMBDA = 0.005  # ~50% decay in ~140 seconds

# Risk level thresholds
RISK_THRESHOLDS = {
    "NORMAL": (0, 30),
    "ELEVATED": (31, 60),
    "SUSPICIOUS": (61, 80),
    "MALICIOUS": (81, 100),
}


class RiskEngine:
    """
    Computes and maintains real-time risk scores using weighted
    multi-signal fusion with exponential time decay.
    """

    def __init__(self):
        self._score_cache = {}  # In-memory cache for fast lookups
        self._last_update = {}

    def compute_risk(self, features):
        """
        Compute risk score from behavioral feature vector.

        Args:
            features: dict from BehaviorAnalyzer.analyze_request()

        Returns:
            dict: Complete risk assessment with score breakdown
        """
        ip = features["ip"]
        now = features["timestamp"]

        # Extract component anomaly scores
        freq_score = features["frequency"].get("anomaly_score", 0)
        fail_score = features["failure"].get("anomaly_score", 0)
        pattern_score = features["pattern"].get("anomaly_score", 0)
        payload_score = features["payload"].get("anomaly_score", 0)
        session_score = features["session"].get("anomaly_score", 0)
        baseline_score = features["baseline_deviation"].get("deviation_score", 0)

        # Apply burst multiplier
        if features["frequency"].get("burst_detected"):
            freq_score = min(100, freq_score * 1.5)

        # Apply acceleration multiplier
        acceleration = features["frequency"].get("acceleration", 1.0)
        if acceleration > 3:
            freq_score = min(100, freq_score * 1.3)

        # Weighted fusion
        raw_score = (
            WEIGHTS["frequency"] * freq_score +
            WEIGHTS["failure"] * fail_score +
            WEIGHTS["pattern"] * pattern_score +
            WEIGHTS["payload"] * payload_score +
            WEIGHTS["session"] * session_score +
            WEIGHTS["baseline"] * baseline_score
        )

        # Apply cross-signal amplification
        # If multiple signals are elevated, the combined risk is more than additive
        elevated_signals = sum(1 for s in [freq_score, fail_score, pattern_score, payload_score]
                                if s > 30)
        if elevated_signals >= 3:
            raw_score = min(100, raw_score * 1.3)
        elif elevated_signals >= 2:
            raw_score = min(100, raw_score * 1.15)

        # Apply exponential decay from previous score
        previous = self._score_cache.get(ip)
        if previous:
            delta_t = now - self._last_update.get(ip, now)
            decay_factor = math.exp(-DECAY_LAMBDA * delta_t)
            # Blend: old score decays, new score contributes
            final_score = decay_factor * previous + (1 - decay_factor) * raw_score
            # But never let the score drop below the current raw assessment
            # if it's significantly high (prevent gaming through pauses)
            if raw_score > 60:
                final_score = max(final_score, raw_score * 0.9)
        else:
            final_score = raw_score

        final_score = round(min(100, max(0, final_score)), 1)

        # Determine risk level
        risk_level = self._classify_risk(final_score)

        # Build result
        result = {
            "ip": ip,
            "current_score": final_score,
            "frequency_score": round(freq_score, 1),
            "failure_score": round(fail_score, 1),
            "pattern_score": round(pattern_score, 1),
            "payload_score": round(payload_score, 1),
            "session_score": round(session_score, 1),
            "baseline_score": round(baseline_score, 1),
            "risk_level": risk_level,
            "elevated_signals": elevated_signals,
            "timestamp": now,
        }

        # Update cache and database
        self._score_cache[ip] = final_score
        self._last_update[ip] = now
        update_risk_score(ip, result)

        # Log significant risk changes
        if risk_level in ("SUSPICIOUS", "MALICIOUS"):
            log_system_event(
                "RISK_ESCALATION",
                "HIGH" if risk_level == "MALICIOUS" else "WARNING",
                source_ip=ip,
                description=f"Risk escalated to {risk_level}: score={final_score}",
                metadata={
                    "score_breakdown": {
                        "frequency": round(freq_score, 1),
                        "failure": round(fail_score, 1),
                        "pattern": round(pattern_score, 1),
                        "payload": round(payload_score, 1),
                    }
                }
            )

        return result

    def get_current_risk(self, ip):
        """Get current risk assessment for an IP."""
        # Check cache first
        if ip in self._score_cache:
            now = time.time()
            delta_t = now - self._last_update.get(ip, now)
            decayed = self._score_cache[ip] * math.exp(-DECAY_LAMBDA * delta_t)
            return {
                "ip": ip,
                "current_score": round(decayed, 1),
                "risk_level": self._classify_risk(decayed),
                "last_updated": self._last_update.get(ip),
            }

        # Fallback to database
        db_score = get_risk_score(ip)
        if db_score:
            return {
                "ip": ip,
                "current_score": db_score["current_score"],
                "risk_level": db_score["risk_level"],
                "last_updated": db_score["last_updated"],
            }

        return {"ip": ip, "current_score": 0, "risk_level": "NORMAL", "last_updated": None}

    def decay_all_scores(self):
        """
        Apply passive decay to all cached scores.
        Called periodically to ensure scores decrease for inactive IPs.
        """
        now = time.time()
        expired = []
        for ip, score in list(self._score_cache.items()):
            delta_t = now - self._last_update.get(ip, now)
            decayed = score * math.exp(-DECAY_LAMBDA * delta_t)
            if decayed < 1:
                expired.append(ip)
            else:
                self._score_cache[ip] = decayed

        for ip in expired:
            del self._score_cache[ip]
            self._last_update.pop(ip, None)

    def _classify_risk(self, score):
        """Classify a numeric score into a risk level."""
        if score <= 30:
            return "NORMAL"
        elif score <= 60:
            return "ELEVATED"
        elif score <= 80:
            return "SUSPICIOUS"
        else:
            return "MALICIOUS"

    def get_all_scores_summary(self):
        """Get summary of all tracked IPs and their scores."""
        from database import get_all_risk_scores
        return get_all_risk_scores()
