"""
self_healing.py - Self-Healing Defense Engine
Auto-generates defense rules from attack patterns without restart.
"""

import re, time, json
from collections import Counter
from database import (
    get_recent_requests, get_active_rules, add_defense_rule,
    log_healing_action, log_system_event, get_healing_log
)


class SelfHealingEngine:
    def __init__(self):
        self._pattern_cache = set()
        self._rule_counter = 0

    def analyze_and_heal(self, ip, risk_assessment, features):
        if risk_assessment["current_score"] < 50:
            return []
        new_rules = []
        new_rules.extend(self._analyze_payload_patterns(ip, features))
        new_rules.extend(self._analyze_behavior_patterns(ip, features, risk_assessment))
        new_rules.extend(self._analyze_scan_patterns(ip, features))
        if new_rules:
            log_system_event("SELF_HEALING", "HIGH", source_ip=ip,
                description=f"Generated {len(new_rules)} new defense rules",
                metadata={"rules": [r["name"] for r in new_rules]})
        return new_rules

    def _analyze_payload_patterns(self, ip, features):
        rules = []
        for flag_type in features["payload"].get("current_flags", []):
            rule = self._generate_payload_rule(flag_type, get_recent_requests(ip, 300))
            if rule:
                rules.append(rule)
        return rules

    def _analyze_behavior_patterns(self, ip, features, risk_assessment):
        rules = []
        failure_data = features["failure"]
        if failure_data["login_failures"] > 5:
            rule_key = f"brute_force_{ip}"
            if rule_key not in self._pattern_cache:
                name = f"Auto_BruteForce_{self._next_id()}"
                add_defense_rule(name, "RATE", f"login:{ip}:max_3/min", "BLOCK", "HIGH", True,
                    f"Brute force from {ip}, {failure_data['login_failures']} failures")
                log_healing_action("BRUTE_FORCE", f"IP={ip}", name)
                self._pattern_cache.add(rule_key)
                rules.append({"name": name, "type": "RATE", "trigger": "brute_force"})

        freq_data = features["frequency"]
        if freq_data["burst_detected"] or freq_data["acceleration"] > 5:
            rule_key = f"burst_{ip}"
            if rule_key not in self._pattern_cache:
                name = f"Auto_Burst_{self._next_id()}"
                add_defense_rule(name, "RATE", f"burst:{ip}:max_5/10s", "THROTTLE", "MEDIUM", True,
                    f"Burst from {ip}, accel={freq_data['acceleration']}x")
                log_healing_action("BURST", f"IP={ip}", name)
                self._pattern_cache.add(rule_key)
                rules.append({"name": name, "type": "RATE", "trigger": "burst"})
        return rules

    def _analyze_scan_patterns(self, ip, features):
        rules = []
        pd = features["pattern"]
        if pd["scan_pattern"] or pd["unique_endpoints"] > 12:
            rule_key = f"scan_{ip}"
            if rule_key not in self._pattern_cache:
                name = f"Auto_Scan_{self._next_id()}"
                add_defense_rule(name, "ACCESS", json.dumps({"blocked_ip": ip}), "BLOCK", "HIGH", True,
                    f"Scan from {ip}, {pd['unique_endpoints']} endpoints")
                log_healing_action("SCAN", f"IP={ip}", name)
                self._pattern_cache.add(rule_key)
                rules.append({"name": name, "type": "ACCESS", "trigger": "scan"})
        if pd.get("enumeration_detected"):
            rule_key = f"enum_{ip}"
            if rule_key not in self._pattern_cache:
                name = f"Auto_Enum_{self._next_id()}"
                add_defense_rule(name, "ACCESS", json.dumps({"blocked_ip": ip, "type": "enum"}), "BLOCK", "HIGH", True,
                    f"Enumeration from {ip}")
                log_healing_action("ENUM", f"IP={ip}", name)
                self._pattern_cache.add(rule_key)
                rules.append({"name": name, "type": "ACCESS", "trigger": "enum"})
        return rules

    def _generate_payload_rule(self, flag_type, recent):
        rule_key = f"payload_{flag_type}_{int(time.time()//300)}"
        if rule_key in self._pattern_cache:
            return None
        configs = {
            "SQL_INJECTION": (r"(\bunion\s+select|or\s+\d+=\d+|drop\s+table|;\s*(drop|delete))", "CRITICAL"),
            "XSS": (r"(<script|javascript:|on(load|error)\s*=|<iframe|<svg\s+onload)", "HIGH"),
            "PATH_TRAVERSAL": (r"(\.\./|%2e%2e|/etc/passwd|/proc/self)", "HIGH"),
            "COMMAND_INJECTION": (r"([;&|`]\s*(cat|whoami|id|curl|wget|nc|bash)|\$\()", "CRITICAL"),
        }
        cfg = configs.get(flag_type)
        if not cfg:
            return None
        name = f"Auto_{flag_type}_{self._next_id()}"
        add_defense_rule(name, "PAYLOAD", cfg[0], "BLOCK", cfg[1], True, f"Auto: {flag_type} pattern")
        log_healing_action(flag_type, cfg[0][:60], name)
        self._pattern_cache.add(rule_key)
        return {"name": name, "type": "PAYLOAD", "trigger": flag_type}

    def check_payload_against_rules(self, payload):
        if not payload:
            return {"blocked": False, "matched_rules": [], "flags": []}
        payload_str = str(payload).lower()
        rules = get_active_rules()
        matched, blocked = [], False
        for rule in rules:
            if rule["rule_type"] != "PAYLOAD":
                continue
            try:
                if rule["pattern"] and re.search(rule["pattern"], payload_str, re.IGNORECASE):
                    matched.append(rule["rule_name"])
                    if rule["action"] == "BLOCK":
                        blocked = True
            except re.error:
                pass
        return {"blocked": blocked, "matched_rules": matched, "flags": matched}

    def _next_id(self):
        self._rule_counter += 1
        return f"{int(time.time())%100000}_{self._rule_counter}"

    def get_healing_status(self):
        active = get_active_rules()
        auto = [r for r in active if r.get("auto_generated")]
        return {
            "total_auto_rules": len(auto),
            "patterns_cached": len(self._pattern_cache),
            "recent_actions": get_healing_log(10),
            "auto_rules": auto,
        }

    def reset_cache(self):
        self._pattern_cache.clear()
        self._rule_counter = 0

    def add_generalized_rule(self, name: str, pattern: str, severity: str, description: str):
        """Allows external modules (like EvolutionController) to inject generalized rules."""
        add_defense_rule(name, "PAYLOAD", pattern, "BLOCK", severity, True, description)
        log_healing_action("GENERALIZED_EVOLUTION", pattern[:60], name)
        log_system_event("GEN_RULE_INJECTED", severity, 
                         description=f"Injected evolve rule: {name}",
                         metadata={"pattern": pattern, "desc": description})
