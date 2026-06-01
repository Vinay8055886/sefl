import re

class ThreatSignatureMatcher:
    def __init__(self):
        # A dictionary mapping threat types to their regex signatures
        self.signatures = {
            "SQLi": [
                re.compile(r"(?i)(UNION.*SELECT|SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM)"),
                re.compile(r"(?i)(\%27|\'|--|\%23|#)"),
                re.compile(r"(?i)(OR\s+1=1|AND\s+1=1|OR\s+'1'='1)"),
            ],
            "XSS": [
                re.compile(r"(?i)(<script.*?>.*?</script>)"),
                re.compile(r"(?i)(javascript:|onerror=|onload=|eval\()"),
                re.compile(r"(?i)(<img.*src=.*onerror=.*>)")
            ],
            "Traversal": [
                re.compile(r"(?i)(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/)"),
                re.compile(r"(?i)(/etc/passwd|/windows/win.ini|cmd\.exe)")
            ],
            "CommandInjection": [
                re.compile(r"(?i)(;|\||&|`|\$|\|\||&&)\s*(ls|cat|ping|wget|curl|nc|bash|sh|whoami)"),
                re.compile(r"(?i)(\b(chmod|chown|rm|mkdir)\b)")
            ],
            "ScannerPatterns": [
                re.compile(r"(?i)(nmap|masscan|zgrab|nikto|dirb|sqlmap|acunetix)")
            ],
            "BruteForce": [
                re.compile(r"(?i)(admin|root|test|guest|user|default)(.*)(password|12345|admin123)")
            ]
        }
        
        self.signature_weights = {
            "SQLi": 80.0,
            "XSS": 75.0,
            "Traversal": 90.0,
            "CommandInjection": 95.0,
            "ScannerPatterns": 50.0,
            "BruteForce": 60.0
        }

    def evaluate_payload(self, payload, user_agent, path):
        # Combine everything that could contain malicious signatures
        target_string = f"{payload} {user_agent} {path}"
        
        matches = []
        total_score = 0.0
        
        for threat_type, patterns in self.signatures.items():
            for pattern in patterns:
                if pattern.search(target_string):
                    if threat_type not in matches:
                        matches.append(threat_type)
                        total_score += self.signature_weights[threat_type]
                    break # Only count the category once
                    
        return {
            "matched_signatures": matches,
            "signature_score": min(total_score, 100.0)
        }
