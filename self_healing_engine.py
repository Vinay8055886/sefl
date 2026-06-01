import time

class SelfHealingEngine:
    def __init__(self):
        self.locked_routes = {}  # route -> expiry time
        self.throttled_identities = {} # fingerprint -> expiry time
        self.sanitize_mode = False
        self.sanitize_mode_expiry = 0
        self.rotated_secret_version = 1
        self.quarantined_fingerprints = set()
        self.deception_mode = False
        self.deception_mode_expiry = 0
        self.action_log = []

    def evaluate_and_heal(self, anomaly_score, fingerprint_confidence, repeat_offender_score, path, matched_signatures, adaptive_action):
        current_time = time.time()
        actions_taken = set()
        
        # Base duration mapping (in seconds) extended by repeat offender score
        base_duration = 300  # 5 minutes
        duration_multiplier = 1 + (repeat_offender_score / 10.0)
        duration = int(base_duration * duration_multiplier)

        sensitive_routes = ['/admin', '/config', '/backup', '/debug', '/login']
        
        # A. temporary_route_lock & G. emergency_maintenance_banner
        if path in sensitive_routes and (anomaly_score > 0.8 or "probe" in str(matched_signatures).lower() or repeat_offender_score > 5 or adaptive_action == "block"):
            self.locked_routes[path] = current_time + duration
            actions_taken.add(f"temporary_route_lock({path})")
            if path != '/login':
                actions_taken.add("emergency_maintenance_banner")

        # B. login_throttle
        if "login" in path.lower() and adaptive_action in ["throttle", "block"] and repeat_offender_score > 3:
            actions_taken.add("login_throttle")

        # C. payload_sanitize_mode
        sql_xss_signatures = ["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL"]
        if any(sig in str(matched_signatures) for sig in sql_xss_signatures) or anomaly_score > 0.9:
            self.sanitize_mode = True
            self.sanitize_mode_expiry = current_time + duration
            actions_taken.add("payload_sanitize_mode")

        # D. fingerprint_quarantine
        if repeat_offender_score > 8 or adaptive_action == "quarantine":
            actions_taken.add("fingerprint_quarantine")

        # E. secret_rotation & F. deception_intensify
        if "/config" in path or "/backup" in path or adaptive_action == "deception_flag":
            self.rotated_secret_version += 1
            self.deception_mode = True
            self.deception_mode_expiry = current_time + duration
            actions_taken.add("secret_rotation")
            actions_taken.add("deception_intensify")

        # Cleanup expired locks
        self._cleanup(current_time)

        return list(actions_taken)

    def apply_quarantine_and_throttle(self, fp_hash, actions_taken, duration=300):
        current_time = time.time()
        if "fingerprint_quarantine" in actions_taken:
            self.quarantined_fingerprints.add(fp_hash)
        if "login_throttle" in actions_taken:
            self.throttled_identities[fp_hash] = current_time + duration
            
    def _cleanup(self, current_time):
        self.locked_routes = {k: v for k, v in self.locked_routes.items() if v > current_time}
        self.throttled_identities = {k: v for k, v in self.throttled_identities.items() if v > current_time}
        if current_time > self.sanitize_mode_expiry:
            self.sanitize_mode = False
        if current_time > self.deception_mode_expiry:
            self.deception_mode = False

    def get_healing_state(self):
        self._cleanup(time.time())
        return {
            "locked_routes": list(self.locked_routes.keys()),
            "throttled_identities": list(self.throttled_identities.keys()),
            "sanitize_mode": self.sanitize_mode,
            "rotated_secret_version": self.rotated_secret_version,
            "quarantined_fingerprints": list(self.quarantined_fingerprints),
            "deception_mode": self.deception_mode
        }
