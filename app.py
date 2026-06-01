import time
import json
import uuid
import logging
from datetime import datetime

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from behavior_memory import BehaviorMemoryEngine
from ml_anomaly_detector import MLAnomalyDetector
from fingerprint_engine import FingerprintEngine
from threat_signatures import ThreatSignatureMatcher
from deception_engine import DeceptionEngine
from adaptive_defense import AdaptiveDefense
from evolution_memory import EvolutionMemory
from forensics_engine import ForensicsEngine
from self_healing_engine import SelfHealingEngine

app = Flask(__name__)
CORS(app)

# In-Memory Storage
RECENT_EVENTS = []
BLOCKED_IPS = set()
QUARANTINED_IDENTITIES = set()
HONEYPOT_TRIGGERS = []
SUSPICIOUS_ENDPOINTS = {}
RISK_HISTORY = []
STATS = {
    "total": 0,
    "allow": 0,
    "block": 0,
    "throttle": 0,
    "quarantine": 0,
    "shadow_monitor": 0,
    "deception_flag": 0
}

# Initialize New AI Components
behavior_memory = BehaviorMemoryEngine()
ml_detector = MLAnomalyDetector()
fingerprint_engine = FingerprintEngine()
threat_signatures = ThreatSignatureMatcher()
deception_engine = DeceptionEngine()
adaptive_defense = AdaptiveDefense()
evolution_memory = EvolutionMemory()
forensics_engine = ForensicsEngine()
self_healing_engine = SelfHealingEngine()

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    ip = data.get("ip", "")
    path = data.get("path", "/")
    method = data.get("method", "GET")
    ua = data.get("user_agent", "")
    payload = data.get("payload", "")
    timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    payload_size = len(payload)
    is_failed_login = method == "POST" and "login" in path.lower() and "failed" in payload.lower() # basic heuristic

    # 1. Fingerprint Engine
    fp_result = fingerprint_engine.evaluate_fingerprint(ip, ua, path, payload, method)
    fp_hash = fp_result["fingerprint_hash"]

    # 2. Deception Engine
    deception_result = deception_engine.evaluate_event(fp_hash, path, method, payload)
    
    # 3. Behavior Memory
    behavior_dev = behavior_memory.update_and_evaluate(
        fp_hash, ip, ua, path, payload_size, 
        deception_result["is_deceptive_hit"], is_failed_login
    )

    # 4. Threat Signatures
    signature_result = threat_signatures.evaluate_payload(payload, ua, path)

    # 5. ML Anomaly
    # Prepare features for ML
    ml_features = {
        "requests_per_minute": len(behavior_memory.memory[fp_hash]["request_timestamps"]) / max((time.time() - behavior_memory.memory[fp_hash]["first_seen"]) / 60, 1),
        "endpoint_diversity": len(set(behavior_memory.memory[fp_hash]["endpoint_sequence"])),
        "sensitive_route_ratio": behavior_memory.memory[fp_hash]["sensitive_endpoint_hits"] / max(behavior_memory.memory[fp_hash]["total_requests"], 1),
        "avg_interval": sum(behavior_memory.memory[fp_hash]["inter_request_intervals"]) / max(len(behavior_memory.memory[fp_hash]["inter_request_intervals"]), 1),
        "payload_entropy": 0.0, # Placeholder, could calculate real entropy if needed
        "failed_auth_ratio": behavior_memory.memory[fp_hash]["failed_login_counts"] / max(behavior_memory.memory[fp_hash]["total_requests"], 1),
        "probe_density": behavior_memory.memory[fp_hash]["burst_density"],
        "header_rarity": 0.0 # Placeholder
    }
    ml_result = ml_detector.predict(ml_features)

    # 6. Evolution Memory (apply multipliers)
    ep_mult, fp_mult, sig_mult = evolution_memory.get_multipliers(path, fp_hash, signature_result["matched_signatures"])

    # Apply multipliers
    adj_behavior_dev = behavior_dev * fp_mult
    adj_ml_prob = ml_result["anomaly_probability"] * fp_mult
    adj_sig_score = signature_result["signature_score"] * sig_mult
    adj_deception_score = deception_result["deception_intent_score"] * ep_mult

    # 7. Adaptive Defense
    defense_decision = adaptive_defense.evaluate_and_respond(
        adj_behavior_dev,
        adj_ml_prob,
        fp_result["confidence"],
        fp_result["repeat_offender_score"],
        adj_sig_score,
        adj_deception_score
    )

    action = defense_decision["action"]
    reason = defense_decision["reason"]
    total_risk = defense_decision["total_risk_score"]

    # 8. Feedback loops & Forensics
    if action in ["block", "quarantine", "deception_flag"]:
        fingerprint_engine.mark_as_attacker(fp_hash)
        evolution_memory.evolve(action, path, fp_hash, signature_result["matched_signatures"])
        
    if total_risk > 50 or action != "allow":
        forensics_engine.log_incident(
            fp_hash, ip, path, payload, ml_result["anomaly_probability"], 
            deception_result["deception_intent_score"], action, signature_result["matched_signatures"]
        )

    # 9. Autonomous Self-Healing
    healing_actions = self_healing_engine.evaluate_and_heal(
        anomaly_score=ml_result["anomaly_probability"],
        fingerprint_confidence=fp_result["confidence"],
        repeat_offender_score=fp_result["repeat_offender_score"],
        path=path,
        matched_signatures=signature_result["matched_signatures"],
        adaptive_action=action
    )
    if healing_actions:
        duration = 300 + int(fp_result["repeat_offender_score"] * 30)
        self_healing_engine.apply_quarantine_and_throttle(fp_hash, healing_actions, duration=duration)
        for act in healing_actions:
            self_healing_engine.action_log.insert(0, {
                "timestamp": timestamp,
                "reason": f"Triggered by {fp_hash[:8]} on {path}",
                "action": act
            })
        if len(self_healing_engine.action_log) > 100:
            self_healing_engine.action_log = self_healing_engine.action_log[:100]

    # Update in-memory dashboard stats
    STATS["total"] += 1
    if action in STATS:
        STATS[action] += 1
    else:
        STATS[action] = 1 # Fallback
        
    event = {
        "ip": ip,
        "path": path,
        "method": method,
        "timestamp": timestamp,
        "decision": action.upper(),
        "score": total_risk,
        "reason": reason,
        "fp_hash": fp_hash[:8]
    }

    RECENT_EVENTS.insert(0, event)
    if len(RECENT_EVENTS) > 100:
        RECENT_EVENTS.pop()

    RISK_HISTORY.append(total_risk)
    if len(RISK_HISTORY) > 50:
        RISK_HISTORY.pop(0)

    if action == "block":
        BLOCKED_IPS.add(ip)
    elif action == "quarantine":
        QUARANTINED_IDENTITIES.add(fp_hash)

    if action == "deception_flag":
        HONEYPOT_TRIGGERS.insert(0, event)
        if len(HONEYPOT_TRIGGERS) > 50:
            HONEYPOT_TRIGGERS.pop()

    if total_risk > 50:
        SUSPICIOUS_ENDPOINTS[path] = SUSPICIOUS_ENDPOINTS.get(path, 0) + 1

    return jsonify({
        "status": "received", 
        "decision": {
            "action": action.upper(),
            "score": total_risk,
            "reason": reason
        }
    })

@app.route("/healing-state", methods=["GET"])
def healing_state():
    return jsonify(self_healing_engine.get_healing_state())

@app.route("/dashboard-data", methods=["GET"])
def dashboard_data():
    recent_risk_avg = sum(RISK_HISTORY[-5:]) / max(1, len(RISK_HISTORY[-5:])) if RISK_HISTORY else 0
    threat_level = "HIGH" if recent_risk_avg > 60 else ("ELEVATED" if recent_risk_avg > 30 else "NORMAL")
    status = "ONLINE" if STATS["total"] > 0 else "IDLE"

    top_endpoints = [{"path": k, "count": v} for k, v in sorted(SUSPICIOUS_ENDPOINTS.items(), key=lambda item: item[1], reverse=True)[:5]]

    # Aggregate forensic summaries and top payloads
    all_forensics = forensics_engine.get_all_reports()
    top_payloads = []
    payload_counts = {}
    for rep in all_forensics:
        for p in rep["payload_attempts"]:
            payload_counts[p] = payload_counts.get(p, 0) + 1
    top_payloads = [{"payload": k, "count": v} for k, v in sorted(payload_counts.items(), key=lambda item: item[1], reverse=True)[:5]]

    return jsonify({
        "stats": STATS,
        "recent_events": RECENT_EVENTS[:20],
        "blocked_ips": list(BLOCKED_IPS),
        "quarantined_identities": list(QUARANTINED_IDENTITIES),
        "honeypot_triggers": HONEYPOT_TRIGGERS[:10],
        "top_endpoints": top_endpoints,
        "risk_history": RISK_HISTORY,
        "status": status,
        "threat_level": threat_level,
        "forensic_summaries": all_forensics[:10],
        "top_malicious_payloads": top_payloads,
        "attacker_fingerprints": len(fingerprint_engine.fingerprints),
        "healing_state": self_healing_engine.get_healing_state(),
        "healing_actions": self_healing_engine.action_log[:20]
    })

if __name__ == "__main__":
    print("==================================================")
    print("AI CYBER DEFENSE MONITORING DASHBOARD v2.0")
    print("==================================================")
    print("PORT:    8000")
    print("STATUS:  Deep Intelligence Engine Active")
    print("==================================================")
    app.run(host="0.0.0.0", port=8000, debug=False)
