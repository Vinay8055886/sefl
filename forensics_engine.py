import time
import uuid

class ForensicsEngine:
    def __init__(self):
        self.reports = {}

    def log_incident(self, fp_hash, ip, path, payload, ml_prob, deception_score, action, matched_signatures):
        if fp_hash not in self.reports:
            self.reports[fp_hash] = {
                "report_id": str(uuid.uuid4()),
                "fingerprint_hash": fp_hash,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "ips_used": set(),
                "endpoints_attacked": set(),
                "anomaly_trend": [],
                "payload_attempts": set(),
                "deception_interactions": 0,
                "response_actions": {},
                "final_classification": "SUSPICIOUS"
            }
            
        report = self.reports[fp_hash]
        
        report["last_seen"] = time.time()
        report["ips_used"].add(ip)
        report["endpoints_attacked"].add(path)
        
        report["anomaly_trend"].append(ml_prob)
        if len(report["anomaly_trend"]) > 10:
            report["anomaly_trend"].pop(0)
            
        if payload and payload != "{}":
            report["payload_attempts"].add(payload[:100]) # Store first 100 chars
            
        if deception_score > 0:
            report["deception_interactions"] += 1
            
        if action not in report["response_actions"]:
            report["response_actions"][action] = 0
        report["response_actions"][action] += 1
        
        # Classification
        if "block" in report["response_actions"] or "quarantine" in report["response_actions"]:
            report["final_classification"] = "MALICIOUS"
        elif report["deception_interactions"] > 2:
            report["final_classification"] = "PROBING_ATTACKER"
            
    def get_all_reports(self):
        # Format sets to lists for JSON serialization
        formatted_reports = []
        for fp, rep in self.reports.items():
            formatted_rep = rep.copy()
            formatted_rep["ips_used"] = list(rep["ips_used"])
            formatted_rep["endpoints_attacked"] = list(rep["endpoints_attacked"])
            formatted_rep["payload_attempts"] = list(rep["payload_attempts"])
            formatted_reports.append(formatted_rep)
        
        # Sort by last seen descending
        formatted_reports.sort(key=lambda x: x["last_seen"], reverse=True)
        return formatted_reports
