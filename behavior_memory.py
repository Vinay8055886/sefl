import sqlite3
import json
import time
import math
from datetime import datetime

class BehaviorMemoryEngine:
    def __init__(self, db_path="behavior_memory.db"):
        self.db_path = db_path
        self._init_db()
        self.memory = {} # In-memory cache for fast access
        self._load_memory()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS visitor_profiles
                     (identity_key TEXT PRIMARY KEY, 
                      profile_data TEXT,
                      last_updated REAL)''')
        conn.commit()
        conn.close()

    def _load_memory(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT identity_key, profile_data FROM visitor_profiles')
        for row in c.fetchall():
            self.memory[row[0]] = json.loads(row[1])
        conn.close()

    def _save_profile(self, identity_key):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        profile_data = json.dumps(self.memory[identity_key])
        c.execute('INSERT OR REPLACE INTO visitor_profiles (identity_key, profile_data, last_updated) VALUES (?, ?, ?)',
                  (identity_key, profile_data, time.time()))
        conn.commit()
        conn.close()

    def _get_default_profile(self):
        return {
            "request_timestamps": [],
            "inter_request_intervals": [],
            "endpoint_sequence": [],
            "failed_login_counts": 0,
            "sensitive_endpoint_hits": 0,
            "total_requests": 0,
            "payload_sizes": [],
            "user_agents": [],
            "first_seen": time.time(),
            "burst_density": 0.0
        }

    def update_and_evaluate(self, identity_key, ip, user_agent, endpoint, payload_size, is_sensitive, is_failed_login):
        now = time.time()
        
        if identity_key not in self.memory:
            self.memory[identity_key] = self._get_default_profile()
            
        profile = self.memory[identity_key]
        
        # Update metrics
        profile["total_requests"] += 1
        if user_agent and user_agent not in profile["user_agents"]:
            profile["user_agents"].append(user_agent)
            
        if is_sensitive:
            profile["sensitive_endpoint_hits"] += 1
            
        if is_failed_login:
            profile["failed_login_counts"] += 1
            
        profile["endpoint_sequence"].append(endpoint)
        if len(profile["endpoint_sequence"]) > 50:
            profile["endpoint_sequence"].pop(0)
            
        profile["payload_sizes"].append(payload_size)
        if len(profile["payload_sizes"]) > 50:
            profile["payload_sizes"].pop(0)

        # Time-based metrics
        profile["request_timestamps"].append(now)
        if len(profile["request_timestamps"]) > 50:
            profile["request_timestamps"].pop(0)
            
        if len(profile["request_timestamps"]) > 1:
            interval = now - profile["request_timestamps"][-2]
            profile["inter_request_intervals"].append(interval)
            if len(profile["inter_request_intervals"]) > 49:
                profile["inter_request_intervals"].pop(0)
                
        # Calculate Burst Density (requests in last 10 seconds)
        recent_burst = [t for t in profile["request_timestamps"] if now - t < 10.0]
        profile["burst_density"] = len(recent_burst)

        self._save_profile(identity_key)
        return self._calculate_deviation(profile)

    def _calculate_deviation(self, profile):
        score = 0.0
        
        # UA inconsistency
        if len(profile["user_agents"]) > 2:
            score += 15.0 * len(profile["user_agents"])
            
        # Burst rate
        if profile["burst_density"] > 10:
            score += min((profile["burst_density"] - 10) * 2.0, 40.0)
            
        # Sensitive hits
        if profile["total_requests"] > 5:
            sensitive_ratio = profile["sensitive_endpoint_hits"] / profile["total_requests"]
            if sensitive_ratio > 0.2:
                score += sensitive_ratio * 50.0
                
        # Failed logins
        score += profile["failed_login_counts"] * 10.0
        
        # Robotic timing
        if len(profile["inter_request_intervals"]) > 5:
            intervals = profile["inter_request_intervals"]
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            if variance < 0.05 and avg_interval < 2.0: # Highly regular, fast requests
                score += 30.0

        return min(score, 100.0)
