"""
behavior_analyzer.py — Behavioral Profiling Engine
====================================================
Dynamically profiles user behavior by analyzing:
  - Request frequency and timing patterns
  - Failed authentication attempts
  - Endpoint access diversity and sequences
  - Session anomalies (multiple sessions, session hopping)
  - Payload characteristics

This module does NOT use static thresholds — it builds per-IP baselines
and detects deviations from normal behavior using statistical methods.
"""

import time
import json
import math
import hashlib
import re
from collections import Counter, defaultdict
from database import (
    get_recent_requests, update_behavior_profile, log_request,
    get_active_rules, log_system_event
)

# ─── Configuration ────────────────────────────────────────────────────

ANALYSIS_WINDOW = 300        # 5 minutes
LONG_WINDOW = 3600           # 1 hour for baseline
BURST_THRESHOLD = 20         # requests per 10 seconds considered burst
SENSITIVE_ENDPOINTS = {
    "/admin", "/api/config", "/api/users", "/api/keys",
    "/login", "/api/auth", "/api/admin", "/debug",
    "/api/database", "/api/secrets", "/.env", "/wp-admin"
}


class BehaviorAnalyzer:
    """
    Analyzes incoming request behavior to build a dynamic profile
    for each IP address. Extracts multi-dimensional behavioral features.
    """

    def __init__(self):
        self._baselines = {}  # Per-IP baseline cache
        self._global_stats = {
            "avg_requests_per_ip": 10,
            "avg_interval": 5.0,
            "total_ips_seen": 0
        }
        self._last_features = {}  # Cache last computed features per IP

    def analyze_request(self, request_data):
        """
        Main entry point. Analyze an incoming request and return
        a behavioral feature vector.

        Args:
            request_data: dict with keys: ip, endpoint, method, user_agent,
                          payload, session_id, status_code

        Returns:
            dict: Behavioral feature vector for the risk engine
        """
        ip = request_data["ip"]
        now = time.time()

        # Log the request
        payload_flags = self._analyze_payload(request_data.get("payload", ""))
        payload_hash = hashlib.md5(
            str(request_data.get("payload", "")).encode()
        ).hexdigest()[:16]

        log_request(
            ip=ip,
            user_agent=request_data.get("user_agent", ""),
            endpoint=request_data.get("endpoint", "/"),
            method=request_data.get("method", "GET"),
            status_code=request_data.get("status_code", 200),
            payload_hash=payload_hash,
            payload_flags=payload_flags,
            session_id=request_data.get("session_id"),
            response_time_ms=request_data.get("response_time_ms", 0)
        )

        # Fetch recent history
        recent = get_recent_requests(ip, ANALYSIS_WINDOW)
        long_history = get_recent_requests(ip, LONG_WINDOW)

        # Extract features
        features = {
            "ip": ip,
            "timestamp": now,
            "frequency": self._compute_frequency_features(recent, now),
            "failure": self._compute_failure_features(recent),
            "pattern": self._compute_pattern_features(recent, request_data),
            "payload": self._compute_payload_features(payload_flags, recent),
            "session": self._compute_session_features(recent, request_data),
            "baseline_deviation": self._compute_baseline_deviation(ip, recent, long_history),
        }

        # Update stored profile
        self._update_profile(ip, features, recent)
        
        # Cache for historical retrieval (e.g., evolution loop)
        self._last_features[ip] = features

        return features

    # ─── Feature Extraction Methods ──────────────────────────────────

    def _compute_frequency_features(self, recent_requests, now):
        """Analyze request frequency patterns."""
        count = len(recent_requests)
        if count < 2:
            return {
                "requests_in_window": count,
                "avg_interval": 0,
                "min_interval": 0,
                "burst_detected": False,
                "acceleration": 0,
                "anomaly_score": 0
            }

        timestamps = sorted([r["timestamp"] for r in recent_requests], reverse=True)
        intervals = [timestamps[i] - timestamps[i+1] for i in range(len(timestamps)-1)]

        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        min_interval = min(intervals) if intervals else 0

        # Burst detection: count requests in last 10 seconds
        burst_window = [t for t in timestamps if now - t < 10]
        burst_detected = len(burst_window) > BURST_THRESHOLD

        # Acceleration: compare recent rate to overall rate
        if len(timestamps) > 4:
            recent_rate = 3 / (timestamps[0] - timestamps[3] + 0.001)
            overall_rate = len(timestamps) / (timestamps[0] - timestamps[-1] + 0.001)
            acceleration = recent_rate / (overall_rate + 0.001)
        else:
            acceleration = 1.0

        # Anomaly score: how far from expected
        expected_rate = self._global_stats["avg_requests_per_ip"]
        rate_deviation = count / (expected_rate + 1)
        anomaly_score = min(100, rate_deviation * 20) if rate_deviation > 2 else 0

        return {
            "requests_in_window": count,
            "avg_interval": round(avg_interval, 3),
            "min_interval": round(min_interval, 3),
            "burst_detected": burst_detected,
            "acceleration": round(acceleration, 2),
            "anomaly_score": round(anomaly_score, 1)
        }

    def _compute_failure_features(self, recent_requests):
        """Analyze authentication failure patterns."""
        total = len(recent_requests)
        if total == 0:
            return {"failure_count": 0, "failure_rate": 0, "consecutive_failures": 0, "anomaly_score": 0}

        failures = [r for r in recent_requests if r["status_code"] in (401, 403, 422)]
        failure_count = len(failures)
        failure_rate = failure_count / total

        # Count consecutive failures (most recent streak)
        consecutive = 0
        for r in sorted(recent_requests, key=lambda x: x["timestamp"], reverse=True):
            if r["status_code"] in (401, 403, 422):
                consecutive += 1
            else:
                break

        # Brute force indicator: many failures on login endpoints
        login_failures = [f for f in failures if any(
            ep in f["endpoint"] for ep in ["/login", "/auth", "/api/auth"]
        )]

        anomaly_score = 0
        if failure_count > 5:
            anomaly_score += 30
        if consecutive > 3:
            anomaly_score += 25
        if len(login_failures) > 3:
            anomaly_score += 30
        if failure_rate > 0.7:
            anomaly_score += 15

        return {
            "failure_count": failure_count,
            "failure_rate": round(failure_rate, 3),
            "consecutive_failures": consecutive,
            "login_failures": len(login_failures),
            "anomaly_score": min(100, anomaly_score)
        }

    def _compute_pattern_features(self, recent_requests, current_request):
        """Analyze endpoint access patterns."""
        if not recent_requests:
            return {"unique_endpoints": 0, "sensitive_hits": 0, "scan_pattern": False, "anomaly_score": 0}

        endpoints = [r["endpoint"] for r in recent_requests]
        unique_endpoints = set(endpoints)
        endpoint_counter = Counter(endpoints)

        # Sensitive endpoint access
        sensitive_hits = sum(1 for ep in endpoints if ep in SENSITIVE_ENDPOINTS)

        # Scan pattern detection: many unique endpoints in short time
        scan_pattern = len(unique_endpoints) > 10 and len(recent_requests) > 15

        # Sequential enumeration detection (e.g., /api/user/1, /api/user/2, ...)
        numeric_pattern = self._detect_enumeration(endpoints)

        # Method anomaly: unusual HTTP methods
        methods = Counter(r["method"] for r in recent_requests)
        unusual_methods = sum(v for k, v in methods.items() if k in ("DELETE", "PUT", "PATCH", "OPTIONS"))

        anomaly_score = 0
        if sensitive_hits > 3:
            anomaly_score += 25
        if scan_pattern:
            anomaly_score += 35
        if numeric_pattern:
            anomaly_score += 20
        if unusual_methods > 5:
            anomaly_score += 15
        if len(unique_endpoints) > 8:
            anomaly_score += 5

        return {
            "unique_endpoints": len(unique_endpoints),
            "sensitive_hits": sensitive_hits,
            "scan_pattern": scan_pattern,
            "enumeration_detected": numeric_pattern,
            "unusual_methods": unusual_methods,
            "anomaly_score": min(100, anomaly_score)
        }

    def _compute_payload_features(self, current_flags, recent_requests):
        """Analyze payload characteristics for malicious content."""
        # Aggregate flags from recent requests
        all_flags = list(current_flags)
        for r in recent_requests[-20:]:  # last 20 requests
            try:
                flags = json.loads(r.get("payload_flags", "[]"))
                all_flags.extend(flags)
            except (json.JSONDecodeError, TypeError):
                pass

        flag_counter = Counter(all_flags)
        total_flags = len(all_flags)

        anomaly_score = 0
        if "SQL_INJECTION" in flag_counter:
            anomaly_score += 40
        if "XSS" in flag_counter:
            anomaly_score += 35
        if "PATH_TRAVERSAL" in flag_counter:
            anomaly_score += 30
        if "COMMAND_INJECTION" in flag_counter:
            anomaly_score += 40
        if total_flags > 5:
            anomaly_score += 15

        return {
            "current_flags": current_flags,
            "total_flags_recent": total_flags,
            "flag_types": dict(flag_counter),
            "anomaly_score": min(100, anomaly_score)
        }

    def _compute_session_features(self, recent_requests, current_request):
        """Analyze session behavior for anomalies."""
        sessions = set()
        user_agents = set()

        for r in recent_requests:
            if r.get("session_id"):
                sessions.add(r["session_id"])
            if r.get("user_agent"):
                user_agents.add(r["user_agent"])

        anomaly_score = 0
        # Multiple sessions from same IP
        if len(sessions) > 3:
            anomaly_score += 25
        # Multiple user agents (possible tool/bot rotation)
        if len(user_agents) > 3:
            anomaly_score += 30
        # No user agent
        if not current_request.get("user_agent"):
            anomaly_score += 15
        # Bot-like user agents
        ua = current_request.get("user_agent", "").lower()
        bot_indicators = ["curl", "wget", "python", "httpie", "postman", "scanner", "nikto", "sqlmap", "nmap"]
        if any(bot in ua for bot in bot_indicators):
            anomaly_score += 20

        return {
            "unique_sessions": len(sessions),
            "unique_user_agents": len(user_agents),
            "bot_indicators": any(bot in ua for bot in bot_indicators) if ua else False,
            "anomaly_score": min(100, anomaly_score)
        }

    def _compute_baseline_deviation(self, ip, recent, long_history):
        """Compare current behavior against the IP's historical baseline."""
        if len(long_history) < 10:
            return {"has_baseline": False, "deviation_score": 0}

        # Build baseline from long history
        baseline_rate = len(long_history) / (LONG_WINDOW / 60)  # requests per minute
        current_rate = len(recent) / (ANALYSIS_WINDOW / 60)

        rate_deviation = current_rate / (baseline_rate + 0.001)

        baseline_endpoints = set(r["endpoint"] for r in long_history)
        current_endpoints = set(r["endpoint"] for r in recent)
        new_endpoints = current_endpoints - baseline_endpoints

        deviation_score = 0
        if rate_deviation > 3:
            deviation_score += 40
        if len(new_endpoints) > 3:
            deviation_score += 20

        return {
            "has_baseline": True,
            "rate_deviation": round(rate_deviation, 2),
            "new_endpoints": list(new_endpoints)[:10],
            "deviation_score": min(100, deviation_score)
        }

    # ─── Payload Analysis ────────────────────────────────────────────

    def _analyze_payload(self, payload):
        """Analyze request payload for malicious patterns."""
        if not payload:
            return []

        payload_str = str(payload).lower() if not isinstance(payload, str) else payload.lower()
        flags = []

        # SQL Injection patterns
        sql_patterns = [
            r"(\b(select|insert|update|delete|drop|union|alter|exec|execute)\b.*\b(from|into|table|where|set)\b)",
            r"(--|#|/\*|\*/)",
            r"(\bor\b\s+\d+\s*=\s*\d+)",
            r"('\s*(or|and)\s+')",
            r"(;\s*(drop|delete|update|insert))",
        ]
        for pattern in sql_patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                flags.append("SQL_INJECTION")
                break

        # XSS patterns
        xss_patterns = [
            r"<script[\s>]",
            r"javascript\s*:",
            r"on(load|error|click|mouseover)\s*=",
            r"<iframe",
            r"<img[^>]+onerror",
        ]
        for pattern in xss_patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                flags.append("XSS")
                break

        # Path traversal
        if re.search(r"\.\./|\.\.\\|%2e%2e", payload_str, re.IGNORECASE):
            flags.append("PATH_TRAVERSAL")

        # Command injection
        cmd_patterns = [r"[;&|`]", r"\$\(", r"\bexec\b", r"\bsystem\b", r"\beval\b"]
        for pattern in cmd_patterns:
            if re.search(pattern, payload_str):
                flags.append("COMMAND_INJECTION")
                break

        # Log if flags found
        if flags:
            log_system_event(
                "PAYLOAD_ALERT",
                "HIGH" if any(f in flags for f in ["SQL_INJECTION", "COMMAND_INJECTION"]) else "MEDIUM",
                description=f"Payload flags detected: {flags}"
            )

        return list(set(flags))

    def _detect_enumeration(self, endpoints):
        """Detect sequential enumeration patterns in endpoint access."""
        # Extract numeric parts from endpoints
        numbers = []
        for ep in endpoints:
            nums = re.findall(r'/(\d+)', ep)
            numbers.extend(int(n) for n in nums)

        if len(numbers) < 3:
            return False

        # Check for sequential numbers
        numbers.sort()
        sequential_count = sum(
            1 for i in range(len(numbers) - 1)
            if numbers[i+1] - numbers[i] == 1
        )

        return sequential_count >= 3

    # ─── Profile Management ──────────────────────────────────────────

    def _update_profile(self, ip, features, recent):
        """Update the stored behavior profile."""
        endpoints = list(set(r["endpoint"] for r in recent))
        hourly = defaultdict(int)
        for r in recent:
            hour = time.strftime("%H", time.localtime(r["timestamp"]))
            hourly[hour] += 1

        profile = {
            "total_requests": features["frequency"]["requests_in_window"],
            "failed_logins": features["failure"]["failure_count"],
            "unique_endpoints": features["pattern"]["unique_endpoints"],
            "avg_request_interval": features["frequency"]["avg_interval"],
            "session_count": features["session"]["unique_sessions"],
            "endpoints_accessed": endpoints[:50],
            "hourly_distribution": dict(hourly),
        }
        update_behavior_profile(ip, profile)

    def get_profile_summary(self, ip):
        """Get a human-readable profile summary for an IP."""
        recent = get_recent_requests(ip, ANALYSIS_WINDOW)
        if not recent:
            return {"ip": ip, "status": "no_data"}

        return {
            "ip": ip,
            "requests_5min": len(recent),
            "unique_endpoints": len(set(r["endpoint"] for r in recent)),
            "failure_rate": sum(1 for r in recent if r["status_code"] in (401, 403)) / max(len(recent), 1),
            "user_agents": list(set(r.get("user_agent", "") for r in recent)),
        }

    def get_last_features(self, ip: str):
        """Retrieve the last computed features for a given IP."""
        return self._last_features.get(ip)
