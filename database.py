"""
database.py — Data Persistence Layer
=====================================
Manages all SQLite operations for the Autonomous Adaptive Cyber Defense System.
Stores behavior logs, risk scores, defense rules, honeypot logs, and blocked IPs.
"""

import sqlite3
import threading
import json
import time
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = "cyber_defense.db"
_local = threading.local()


def get_connection():
    """Thread-safe SQLite connection."""
    if not hasattr(_local, "connection") or _local.connection is None:
        _local.connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.connection.row_factory = sqlite3.Row
        _local.connection.execute("PRAGMA journal_mode=WAL")
        _local.connection.execute("PRAGMA foreign_keys=ON")
    return _local.connection


@contextmanager
def get_db():
    """Context manager for database operations."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_database():
    """Initialize all database tables."""
    with get_db() as conn:
        conn.executescript("""
            -- Request logs for behavior analysis
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER,
                payload_hash TEXT,
                payload_flags TEXT DEFAULT '[]',
                timestamp REAL NOT NULL,
                session_id TEXT,
                response_time_ms REAL
            );

            -- User behavior profiles
            CREATE TABLE IF NOT EXISTS behavior_profiles (
                ip_address TEXT PRIMARY KEY,
                total_requests INTEGER DEFAULT 0,
                failed_logins INTEGER DEFAULT 0,
                unique_endpoints INTEGER DEFAULT 0,
                avg_request_interval REAL DEFAULT 0,
                last_seen REAL,
                session_count INTEGER DEFAULT 0,
                endpoints_accessed TEXT DEFAULT '[]',
                hourly_distribution TEXT DEFAULT '{}',
                created_at REAL,
                updated_at REAL
            );

            -- Real-time risk scores
            CREATE TABLE IF NOT EXISTS risk_scores (
                ip_address TEXT PRIMARY KEY,
                current_score REAL DEFAULT 0,
                frequency_score REAL DEFAULT 0,
                failure_score REAL DEFAULT 0,
                pattern_score REAL DEFAULT 0,
                payload_score REAL DEFAULT 0,
                session_score REAL DEFAULT 0,
                risk_level TEXT DEFAULT 'NORMAL',
                last_updated REAL,
                score_history TEXT DEFAULT '[]'
            );

            -- Active defense rules (dynamic)
            CREATE TABLE IF NOT EXISTS defense_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                pattern TEXT,
                action TEXT NOT NULL,
                severity TEXT DEFAULT 'MEDIUM',
                is_active INTEGER DEFAULT 1,
                triggered_count INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.5,
                expires_at REAL,
                description TEXT
            );

            -- Blocked IPs
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at REAL,
                expires_at REAL,
                is_permanent INTEGER DEFAULT 0,
                risk_score_at_block REAL
            );

            -- Honeypot interaction logs
            CREATE TABLE IF NOT EXISTS honeypot_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                headers TEXT,
                payload TEXT,
                user_agent TEXT,
                timestamp REAL NOT NULL,
                session_id TEXT,
                interaction_type TEXT
            );

            -- System events and alerts
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT,
                metadata TEXT DEFAULT '{}',
                timestamp REAL NOT NULL
            );

            -- Defense state
            CREATE TABLE IF NOT EXISTS defense_state (
                id INTEGER PRIMARY KEY DEFAULT 1,
                current_level INTEGER DEFAULT 0,
                rate_limit INTEGER DEFAULT 60,
                escalation_reason TEXT,
                last_changed REAL
            );

            -- Self-healing rule generation log
            CREATE TABLE IF NOT EXISTS healing_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                pattern_detected TEXT,
                rule_generated TEXT,
                applied_at REAL,
                effectiveness_score REAL DEFAULT 0
            );

            -- Attack signatures / knowledge base
            CREATE TABLE IF NOT EXISTS attack_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_hash TEXT UNIQUE NOT NULL,
                attack_type TEXT,
                payload_pattern TEXT,
                behavior_fingerprint TEXT,
                feature_vector TEXT DEFAULT '[]',
                first_seen REAL,
                last_seen REAL,
                occurrence_count INTEGER DEFAULT 1,
                source_ips TEXT DEFAULT '[]',
                severity TEXT DEFAULT 'MEDIUM',
                confidence REAL DEFAULT 0.5,
                metadata TEXT DEFAULT '{}'
            );

            -- Cross-IP correlation campaigns
            CREATE TABLE IF NOT EXISTS attack_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT UNIQUE NOT NULL,
                member_ips TEXT DEFAULT '[]',
                common_payloads TEXT DEFAULT '[]',
                common_behaviors TEXT DEFAULT '[]',
                similarity_score REAL DEFAULT 0,
                detected_at REAL,
                last_updated REAL,
                status TEXT DEFAULT 'ACTIVE',
                metadata TEXT DEFAULT '{}'
            );

            -- Evolution event log
            CREATE TABLE IF NOT EXISTS evolution_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                description TEXT,
                old_value TEXT,
                new_value TEXT,
                improvement_metric REAL DEFAULT 0,
                timestamp REAL
            );

            -- ML model state persistence
            CREATE TABLE IF NOT EXISTS model_state (
                id INTEGER PRIMARY KEY DEFAULT 1,
                anomaly_model_data BLOB,
                training_samples_count INTEGER DEFAULT 0,
                last_trained REAL,
                model_accuracy REAL DEFAULT 0,
                feature_means TEXT DEFAULT '{}',
                feature_stds TEXT DEFAULT '{}',
                normal_profile TEXT DEFAULT '{}',
                metadata TEXT DEFAULT '{}'
            );

            -- Rule effectiveness tracking
            CREATE TABLE IF NOT EXISTS rule_effectiveness (
                rule_id INTEGER PRIMARY KEY,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                true_negatives INTEGER DEFAULT 0,
                false_negatives INTEGER DEFAULT 0,
                effectiveness_score REAL DEFAULT 0.5,
                last_evaluated REAL
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip_address);
            CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_request_logs_endpoint ON request_logs(endpoint);
            CREATE INDEX IF NOT EXISTS idx_honeypot_logs_ip ON honeypot_logs(ip_address);
            CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_attack_signatures_hash ON attack_signatures(signature_hash);
            CREATE INDEX IF NOT EXISTS idx_attack_signatures_type ON attack_signatures(attack_type);
            CREATE INDEX IF NOT EXISTS idx_attack_campaigns_status ON attack_campaigns(status);
        """)

        # Insert default defense state if not exists
        conn.execute("""
            INSERT OR IGNORE INTO defense_state (id, current_level, rate_limit, last_changed)
            VALUES (1, 0, 60, ?)
        """, (time.time(),))

        # Insert default defense rules
        default_rules = [
            ("SQL Injection Basic", "PAYLOAD", r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)", "BLOCK", "HIGH", "Blocks common SQL injection keywords"),
            ("XSS Script Tags", "PAYLOAD", r"<script[\s>]", "BLOCK", "HIGH", "Blocks script tag injection"),
            ("Path Traversal", "PAYLOAD", r"\.\./|\.\.\\", "BLOCK", "MEDIUM", "Blocks directory traversal attempts"),
            ("Command Injection", "PAYLOAD", r"[;&|`$]", "FLAG", "MEDIUM", "Flags potential command injection characters"),
            ("Rate Limit Default", "RATE", "60/minute", "THROTTLE", "LOW", "Default rate limiting rule"),
        ]
        for name, rtype, pattern, action, severity, desc in default_rules:
            conn.execute("""
                INSERT OR IGNORE INTO defense_rules (rule_name, rule_type, pattern, action, severity, created_at, description)
                SELECT ?, ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM defense_rules WHERE rule_name = ?)
            """, (name, rtype, pattern, action, severity, time.time(), desc, name))


# ─── Query Helpers ───────────────────────────────────────────────────────

def log_request(ip, user_agent, endpoint, method, status_code, payload_hash="", payload_flags=None, session_id=None, response_time_ms=0):
    """Log an incoming request."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO request_logs (ip_address, user_agent, endpoint, method, status_code, payload_hash, payload_flags, timestamp, session_id, response_time_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, user_agent, endpoint, method, status_code, payload_hash,
              json.dumps(payload_flags or []), time.time(), session_id, response_time_ms))


def get_recent_requests(ip, window_seconds=300):
    """Get recent requests from an IP within a time window."""
    with get_db() as conn:
        cutoff = time.time() - window_seconds
        rows = conn.execute("""
            SELECT * FROM request_logs WHERE ip_address = ? AND timestamp > ? ORDER BY timestamp DESC
        """, (ip, cutoff)).fetchall()
        return [dict(r) for r in rows]


def update_behavior_profile(ip, profile_data):
    """Upsert a behavior profile."""
    with get_db() as conn:
        now = time.time()
        conn.execute("""
            INSERT INTO behavior_profiles (ip_address, total_requests, failed_logins, unique_endpoints,
                avg_request_interval, last_seen, session_count, endpoints_accessed, hourly_distribution, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                total_requests = excluded.total_requests,
                failed_logins = excluded.failed_logins,
                unique_endpoints = excluded.unique_endpoints,
                avg_request_interval = excluded.avg_request_interval,
                last_seen = excluded.last_seen,
                session_count = excluded.session_count,
                endpoints_accessed = excluded.endpoints_accessed,
                hourly_distribution = excluded.hourly_distribution,
                updated_at = excluded.updated_at
        """, (ip, profile_data.get("total_requests", 0), profile_data.get("failed_logins", 0),
              profile_data.get("unique_endpoints", 0), profile_data.get("avg_request_interval", 0),
              now, profile_data.get("session_count", 0),
              json.dumps(profile_data.get("endpoints_accessed", [])),
              json.dumps(profile_data.get("hourly_distribution", {})),
              now, now))


def update_risk_score(ip, scores):
    """Upsert risk score data."""
    with get_db() as conn:
        history_entry = json.dumps({"score": scores["current_score"], "time": time.time()})
        conn.execute("""
            INSERT INTO risk_scores (ip_address, current_score, frequency_score, failure_score,
                pattern_score, payload_score, session_score, risk_level, last_updated, score_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, json_array(?))
            ON CONFLICT(ip_address) DO UPDATE SET
                current_score = excluded.current_score,
                frequency_score = excluded.frequency_score,
                failure_score = excluded.failure_score,
                pattern_score = excluded.pattern_score,
                payload_score = excluded.payload_score,
                session_score = excluded.session_score,
                risk_level = excluded.risk_level,
                last_updated = excluded.last_updated
        """, (ip, scores["current_score"], scores.get("frequency_score", 0),
              scores.get("failure_score", 0), scores.get("pattern_score", 0),
              scores.get("payload_score", 0), scores.get("session_score", 0),
              scores.get("risk_level", "NORMAL"), time.time(), history_entry))


def get_risk_score(ip):
    """Get current risk score for an IP."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM risk_scores WHERE ip_address = ?", (ip,)).fetchone()
        return dict(row) if row else None


def get_all_risk_scores():
    """Get all risk scores."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM risk_scores ORDER BY current_score DESC").fetchall()
        return [dict(r) for r in rows]


def block_ip(ip, reason, duration_seconds=3600, permanent=False, risk_score=0):
    """Block an IP address."""
    with get_db() as conn:
        now = time.time()
        expires = None if permanent else now + duration_seconds
        conn.execute("""
            INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_at, expires_at, is_permanent, risk_score_at_block)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, reason, now, expires, 1 if permanent else 0, risk_score))


def unblock_ip(ip):
    """Unblock an IP address."""
    with get_db() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))


def is_ip_blocked(ip):
    """Check if an IP is currently blocked."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip,)).fetchone()
        if not row:
            return False
        if row["is_permanent"]:
            return True
        if row["expires_at"] and time.time() > row["expires_at"]:
            conn.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
            return False
        return True


def get_blocked_ips():
    """Get all currently blocked IPs."""
    with get_db() as conn:
        now = time.time()
        rows = conn.execute("""
            SELECT * FROM blocked_ips WHERE is_permanent = 1 OR expires_at > ?
            ORDER BY blocked_at DESC
        """, (now,)).fetchall()
        return [dict(r) for r in rows]


def log_honeypot(ip, endpoint, method, headers, payload, user_agent, session_id=None, interaction_type="ACCESS"):
    """Log honeypot interaction."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO honeypot_logs (ip_address, endpoint, method, headers, payload, user_agent, timestamp, session_id, interaction_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, endpoint, method, json.dumps(headers) if isinstance(headers, dict) else headers,
              payload, user_agent, time.time(), session_id, interaction_type))


def get_honeypot_logs(limit=100):
    """Get recent honeypot logs."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM honeypot_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def add_defense_rule(name, rule_type, pattern, action, severity="MEDIUM", auto_generated=False, description="", ttl=86400):
    """Add a new defense rule with optional TTL (default 24h for auto-generated)."""
    with get_db() as conn:
        expires_at = time.time() + ttl if ttl else None
        conn.execute("""
            INSERT INTO defense_rules (rule_name, rule_type, pattern, action, severity, is_active, auto_generated, created_at, confidence, expires_at, description)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        """, (name, rule_type, pattern, action, severity, 1 if auto_generated else 0, time.time(), 0.7 if auto_generated else 1.0, expires_at, description))


def decay_risk_scores(decay_factor=0.9):
    """Gradually reduce risk scores over time to allow for 'rehabilitation'."""
    with get_db() as conn:
        # Simple implementation for now
        # In a real app we'd iterate and log
        res = conn.execute("UPDATE risk_scores SET current_score = current_score * ?", (decay_factor,))
        # Also clean up behavior profiles or other decaying metrics if needed
        return res.rowcount


def cleanup_expired_rules():
    """Remove rules that have passed their expiration time."""
    with get_db() as conn:
        res = conn.execute("DELETE FROM defense_rules WHERE expires_at IS NOT NULL AND expires_at < ?", (time.time(),))
        return res.rowcount


def get_active_rules():
    """Get all active defense rules."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM defense_rules WHERE is_active = 1 ORDER BY severity DESC").fetchall()
        return [dict(r) for r in rows]


def get_defense_state():
    """Get current defense state."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM defense_state WHERE id = 1").fetchone()
        return dict(row) if row else {"current_level": 0, "rate_limit": 60}


def update_defense_state(level, rate_limit, reason=""):
    """Update defense state."""
    with get_db() as conn:
        conn.execute("""
            UPDATE defense_state SET current_level = ?, rate_limit = ?, escalation_reason = ?, last_changed = ?
            WHERE id = 1
        """, (level, rate_limit, reason, time.time()))


def log_system_event(event_type, severity, source_ip=None, description="", metadata=None):
    """Log a system event."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO system_events (event_type, severity, source_ip, description, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_type, severity, source_ip, description, json.dumps(metadata or {}), time.time()))


def get_system_events(limit=200, event_type=None):
    """Get system events with optional type filter."""
    with get_db() as conn:
        if event_type:
            rows = conn.execute("""
                SELECT * FROM system_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?
            """, (event_type, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM system_events ORDER BY timestamp DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def log_healing_action(attack_type, pattern, rule_name):
    """Log a self-healing action."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO healing_log (attack_type, pattern_detected, rule_generated, applied_at)
            VALUES (?, ?, ?, ?)
        """, (attack_type, pattern, rule_name, time.time()))


def get_healing_log(limit=50):
    """Get self-healing log."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM healing_log ORDER BY applied_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_dashboard_stats():
    """Get aggregated statistics for the dashboard."""
    with get_db() as conn:
        now = time.time()
        hour_ago = now - 3600

        stats = {
            "total_requests_1h": conn.execute(
                "SELECT COUNT(*) FROM request_logs WHERE timestamp > ?", (hour_ago,)
            ).fetchone()[0],
            "unique_ips_1h": conn.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM request_logs WHERE timestamp > ?", (hour_ago,)
            ).fetchone()[0],
            "blocked_ips_count": conn.execute(
                "SELECT COUNT(*) FROM blocked_ips WHERE is_permanent = 1 OR expires_at > ?", (now,)
            ).fetchone()[0],
            "active_rules_count": conn.execute(
                "SELECT COUNT(*) FROM defense_rules WHERE is_active = 1"
            ).fetchone()[0],
            "honeypot_interactions_1h": conn.execute(
                "SELECT COUNT(*) FROM honeypot_logs WHERE timestamp > ?", (hour_ago,)
            ).fetchone()[0],
            "auto_generated_rules": conn.execute(
                "SELECT COUNT(*) FROM defense_rules WHERE auto_generated = 1 AND is_active = 1"
            ).fetchone()[0],
            "high_risk_ips": conn.execute(
                "SELECT COUNT(*) FROM risk_scores WHERE current_score > 60"
            ).fetchone()[0],
            "defense_state": dict(conn.execute("SELECT * FROM defense_state WHERE id = 1").fetchone()),
        }
        return stats


def update_rule_effectiveness(rule_name, is_true_positive):
    """Update effectiveness metrics for a defense rule."""
    with get_db() as conn:
        # Get rule_id from name
        row = conn.execute("SELECT id FROM defense_rules WHERE rule_name = ?", (rule_name,)).fetchone()
        if not row:
            return
        rule_id = row["id"]

        # Insert or update effectiveness record
        conn.execute("""
            INSERT INTO rule_effectiveness (rule_id, true_positives, false_positives, last_evaluated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                true_positives = true_positives + excluded.true_positives,
                false_positives = false_positives + excluded.false_positives,
                last_evaluated = excluded.last_evaluated
        """, (
            rule_id,
            1 if is_true_positive else 0,
            0 if is_true_positive else 1,
            time.time()
        ))

        # Recalculate effectiveness score and update rule confidence
        conn.execute("""
            UPDATE rule_effectiveness
            SET effectiveness_score = CAST(true_positives + 1 AS REAL) / (true_positives + false_positives + 2)
            WHERE rule_id = ?
        """, (rule_id,))
        
        # Pull score to rule confidence
        conn.execute("""
            UPDATE defense_rules
            SET confidence = (SELECT effectiveness_score FROM rule_effectiveness WHERE rule_id = ?)
            WHERE id = ?
        """, (rule_id, rule_id))


def update_attack_signature_confidence(signature_hash, delta):
    """Adjust confidence of an attack signature based on validation."""
    with get_db() as conn:
        conn.execute("""
            UPDATE attack_signatures
            SET confidence = MAX(0.0, MIN(1.0, confidence + ?))
            WHERE signature_hash = ?
        """, (delta, signature_hash))


def get_rule_performance():
    """Get performance metrics for all rules."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT r.rule_name, e.*
            FROM defense_rules r
            JOIN rule_effectiveness e ON r.id = e.rule_id
            ORDER BY e.effectiveness_score DESC
        """).fetchall()
        return [dict(r) for r in rows]
