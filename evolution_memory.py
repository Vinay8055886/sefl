class EvolutionMemory:
    def __init__(self):
        self.endpoint_sensitivity = {}
        self.payload_weights = {}
        self.fingerprint_risk_multipliers = {}

    def evolve(self, action, path, fp_hash, matched_signatures):
        """
        Adapts the defense system based on severe defensive actions taken.
        """
        # If we blocked or quarantined, we must evolve to be harsher next time
        if action in ["block", "quarantine", "deception_flag"]:
            # 1. Raise sensitivity of attacked endpoint
            if path not in self.endpoint_sensitivity:
                self.endpoint_sensitivity[path] = 1.0
            self.endpoint_sensitivity[path] += 0.1
            
            # 2. Increase fingerprint prior risk multiplier
            if fp_hash not in self.fingerprint_risk_multipliers:
                self.fingerprint_risk_multipliers[fp_hash] = 1.0
            self.fingerprint_risk_multipliers[fp_hash] += 0.25
            
            # 3. Strengthen payload blacklist weight for matching signatures
            for sig in matched_signatures:
                if sig not in self.payload_weights:
                    self.payload_weights[sig] = 1.0
                self.payload_weights[sig] += 0.15

    def get_multipliers(self, path, fp_hash, matched_signatures):
        """
        Returns the current evolution multipliers to be applied to raw scores.
        """
        ep_mult = self.endpoint_sensitivity.get(path, 1.0)
        fp_mult = self.fingerprint_risk_multipliers.get(fp_hash, 1.0)
        
        sig_mult = 1.0
        if matched_signatures:
            # Average multiplier of matched signatures
            sig_mult = sum([self.payload_weights.get(sig, 1.0) for sig in matched_signatures]) / len(matched_signatures)
            
        return ep_mult, fp_mult, sig_mult
