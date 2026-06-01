import time

class DeceptionEngine:
    def __init__(self):
        self.deceptive_routes = [
            "/admin",
            "/config",
            "/backup",
            "/debug",
            "/.env",
            "/wp-admin",
            "/setup"
        ]
        # In-memory tracking per identity (fingerprint or IP)
        self.deception_profiles = {}

    def _get_default_profile(self):
        return {
            "curiosity_count": 0,
            "route_dwell_times": [],
            "last_seen_route": None,
            "last_seen_time": None,
            "repeated_secret_probing": 0,
            "fake_credentials_submitted": 0
        }

    def evaluate_event(self, identity_key, path, method, payload):
        is_deceptive = False
        
        # Check if targeting deceptive route
        path_lower = path.lower()
        if any(r in path_lower for r in self.deceptive_routes):
            is_deceptive = True
            
        # Or if payload contains fake credential patterns
        # For simplicity, we assume if it's a POST to a deceptive route, it's a fake submission
        is_fake_submission = is_deceptive and method == "POST"

        if not is_deceptive and not is_fake_submission:
            if identity_key in self.deception_profiles:
                return {
                    "is_deceptive_hit": False,
                    "deception_intent_score": self._calculate_intent_score(self.deception_profiles[identity_key])
                }
            return {
                "is_deceptive_hit": False,
                "deception_intent_score": 0.0
            }

        if identity_key not in self.deception_profiles:
            self.deception_profiles[identity_key] = self._get_default_profile()
            
        profile = self.deception_profiles[identity_key]
        now = time.time()
        
        profile["curiosity_count"] += 1
        
        # Check for repeated probing
        if profile["last_seen_route"] == path:
            profile["repeated_secret_probing"] += 1
            
        # Dwell time calculation (if they move between deceptive routes quickly)
        if profile["last_seen_time"]:
            dwell = now - profile["last_seen_time"]
            if dwell < 60: # If they hit another deceptive route within 60s
                profile["route_dwell_times"].append(dwell)
                
        if is_fake_submission:
            profile["fake_credentials_submitted"] += 1
            
        profile["last_seen_route"] = path
        profile["last_seen_time"] = now

        return {
            "is_deceptive_hit": True,
            "deception_intent_score": self._calculate_intent_score(profile)
        }

    def _calculate_intent_score(self, profile):
        score = 0.0
        
        # Base curiosity
        score += profile["curiosity_count"] * 15.0
        
        # Repeated probing indicates determination
        score += profile["repeated_secret_probing"] * 20.0
        
        # Submitting fake credentials is a huge red flag
        score += profile["fake_credentials_submitted"] * 40.0
        
        # Fast traversal of deceptive routes (scanner behavior)
        if profile["route_dwell_times"]:
            avg_dwell = sum(profile["route_dwell_times"]) / len(profile["route_dwell_times"])
            if avg_dwell < 5.0: # Very fast probing
                score += 30.0

        return min(score, 100.0)
