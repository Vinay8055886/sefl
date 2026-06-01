import hashlib
import json
import time

class FingerprintEngine:
    def __init__(self):
        self.fingerprints = {}

    def _generate_hash(self, user_agent, path, payload, method):
        # A simple fingerprint hash based on static/semi-static elements of a request
        # Endpoint ordering and timing rhythm are dynamic and handled in the behavioral profile, 
        # but here we identify the 'tool' or 'actor' footprint.
        components = f"{user_agent}|{path}|{method}|{payload[:50]}"
        return hashlib.sha256(components.encode()).hexdigest()

    def evaluate_fingerprint(self, ip, user_agent, path, payload, method):
        fp_hash = self._generate_hash(user_agent, path, payload, method)
        
        if fp_hash not in self.fingerprints:
            self.fingerprints[fp_hash] = {
                "ips_seen": set(),
                "confidence": 0.0,
                "prior_attack_history": 0,
                "repeat_offender_score": 0.0,
                "first_seen": time.time(),
                "last_seen": time.time()
            }
            
        fp_data = self.fingerprints[fp_hash]
        fp_data["ips_seen"].add(ip)
        fp_data["last_seen"] = time.time()
        
        # Increase confidence as we see this fingerprint more across different IPs
        ip_count = len(fp_data["ips_seen"])
        if ip_count > 1:
            fp_data["confidence"] = min(1.0, 0.5 + (ip_count * 0.1))
        else:
            fp_data["confidence"] = 0.5

        return {
            "fingerprint_hash": fp_hash,
            "confidence": fp_data["confidence"],
            "prior_attack_history": fp_data["prior_attack_history"],
            "repeat_offender_score": fp_data["repeat_offender_score"],
            "known_ips": list(fp_data["ips_seen"])
        }

    def mark_as_attacker(self, fp_hash):
        if fp_hash in self.fingerprints:
            self.fingerprints[fp_hash]["prior_attack_history"] += 1
            self.fingerprints[fp_hash]["repeat_offender_score"] += 25.0
            self.fingerprints[fp_hash]["repeat_offender_score"] = min(100.0, self.fingerprints[fp_hash]["repeat_offender_score"])
