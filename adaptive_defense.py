class AdaptiveDefense:
    def __init__(self):
        pass

    def evaluate_and_respond(self, behavior_dev, ml_prob, fp_confidence, fp_repeat_score, signature_score, deception_score):
        """
        Synthesizes multiple intelligence vectors into a final autonomous response.
        """
        # Calculate a weighted total risk score
        # Base values typically 0-100, ml_prob is 0.0-1.0
        
        ml_score = ml_prob * 100.0
        
        total_risk = (
            (behavior_dev * 0.15) +
            (ml_score * 0.20) +
            (fp_repeat_score * 0.10) +
            (signature_score * 0.30) +
            (deception_score * 0.25)
        )
        
        # Determine the action based on thresholds and specific severe indicators
        action = "allow"
        reason = "Normal behavior"
        
        if signature_score > 90:
            action = "block"
            reason = "Critical payload signature match"
        elif deception_score > 80:
            action = "deception_flag"
            reason = "High deception intent"
        elif total_risk > 85:
            action = "block"
            reason = f"Combined extreme risk score ({total_risk:.1f})"
        elif total_risk > 70:
            action = "quarantine"
            reason = f"High risk score ({total_risk:.1f}) - isolation required"
        elif total_risk > 50:
            action = "throttle"
            reason = f"Elevated risk ({total_risk:.1f}) - rate limiting applied"
        elif ml_score > 75 or behavior_dev > 70:
            action = "shadow_monitor"
            reason = "Anomalous patterns detected - silent monitoring engaged"
            
        return {
            "action": action,
            "total_risk_score": total_risk,
            "reason": reason
        }
