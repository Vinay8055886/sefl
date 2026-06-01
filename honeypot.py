"""
honeypot.py — Deception System with Forensic Logging
=====================================================
Creates a realistic fake environment for attackers. Suspicious users
are transparently redirected to fake endpoints that mimic real services.
All interactions are forensically logged for analysis.

Fake Endpoints:
  /admin          → Fake admin panel with login form
  /api/users      → Fake user data (synthetic)
  /api/config     → Fake configuration data
  /api/keys       → Fake API keys
  /api/database   → Fake database dump
  /debug          → Fake debug console
  /.env           → Fake environment variables
  /wp-admin       → Fake WordPress admin

Every interaction inside the honeypot is logged with full request details
including headers, payload, timing, and session tracking.
"""

import time
import json
import random
import string
import hashlib
from flask import Blueprint, request, jsonify, render_template_string
from database import log_honeypot, log_system_event, get_honeypot_logs

honeypot_bp = Blueprint("honeypot", __name__)

# Threat confirmation callback (set by app.py to EvolutionController)
_threat_callback = None


def register_threat_callback(fn):
    """Register a callback to be notified when a threat is confirmed."""
    global _threat_callback
    _threat_callback = fn

# ─── Fake Data Generators ─────────────────────────────────────────────


def _fake_api_key():
    """Generate a realistic-looking fake API key."""
    prefix = random.choice(["sk_live_", "pk_test_", "api_key_", "bearer_"])
    body = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return prefix + body


def _fake_user():
    """Generate a fake user record."""
    first_names = ["James", "Sarah", "Mike", "Emily", "David", "Lisa", "Robert", "Anna"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    fn = random.choice(first_names)
    ln = random.choice(last_names)
    return {
        "id": random.randint(1000, 9999),
        "username": f"{fn.lower()}.{ln.lower()}",
        "email": f"{fn.lower()}.{ln.lower()}@company-internal.com",
        "role": random.choice(["admin", "user", "moderator", "superadmin"]),
        "last_login": f"2026-04-{random.randint(1,6):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
        "status": "active",
        "api_key": _fake_api_key(),
    }


def _fake_config():
    """Generate fake configuration data."""
    return {
        "database": {
            "host": "db-primary.internal.company.net",
            "port": 5432,
            "name": "production_main",
            "user": "app_service",
            "password": "Pr0d_" + ''.join(random.choices(string.ascii_letters, k=12)),
        },
        "redis": {
            "host": "cache-01.internal.company.net",
            "port": 6379,
            "password": ''.join(random.choices(string.ascii_letters + string.digits, k=20)),
        },
        "aws": {
            "access_key": "AKIA" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)),
            "secret_key": ''.join(random.choices(string.ascii_letters + string.digits + "+/", k=40)),
            "region": "us-east-1",
            "s3_bucket": "company-production-data",
        },
        "jwt_secret": ''.join(random.choices(string.ascii_letters + string.digits, k=64)),
        "encryption_key": hashlib.sha256(str(random.random()).encode()).hexdigest(),
        "smtp": {
            "host": "smtp.company.net",
            "port": 587,
            "user": "noreply@company.com",
            "password": "Smtp_" + ''.join(random.choices(string.ascii_letters, k=10)),
        }
    }


def _fake_env():
    """Generate fake .env file content."""
    config = _fake_config()
    lines = [
        f'DATABASE_URL=postgresql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}/{config["database"]["name"]}',
        f'REDIS_URL=redis://:{config["redis"]["password"]}@{config["redis"]["host"]}:{config["redis"]["port"]}/0',
        f'AWS_ACCESS_KEY_ID={config["aws"]["access_key"]}',
        f'AWS_SECRET_ACCESS_KEY={config["aws"]["secret_key"]}',
        f'JWT_SECRET={config["jwt_secret"]}',
        f'ENCRYPTION_KEY={config["encryption_key"]}',
        'DEBUG=false',
        'NODE_ENV=production',
        f'SMTP_PASSWORD={config["smtp"]["password"]}',
        f'API_SECRET_KEY={_fake_api_key()}',
    ]
    return '\n'.join(lines)


# ─── Honeypot Logging Decorator ──────────────────────────────────────

def _log_interaction(endpoint, interaction_type="ACCESS"):
    """Log a honeypot interaction with full forensic detail."""
    ip = request.remote_addr
    headers = dict(request.headers)
    payload = ""
    try:
        if request.is_json:
            payload = json.dumps(request.get_json(silent=True))
        elif request.form:
            payload = json.dumps(dict(request.form))
        elif request.data:
            payload = request.data.decode("utf-8", errors="replace")[:2000]
    except Exception:
        payload = "<unparseable>"

    log_honeypot(
        ip=ip,
        endpoint=endpoint,
        method=request.method,
        headers=headers,
        payload=payload,
        user_agent=request.headers.get("User-Agent", ""),
        session_id=request.cookies.get("session_id"),
        interaction_type=interaction_type,
    )

    log_system_event(
        "HONEYPOT_INTERACTION",
        "HIGH",
        source_ip=ip,
        description=f"Honeypot accessed: {request.method} {endpoint}",
        metadata={"user_agent": request.headers.get("User-Agent", ""), "type": interaction_type}
    )

    # Notify EvolutionController if registered
    if _threat_callback:
        try:
            _threat_callback(ip, payload, endpoint, interaction_type)
        except Exception as e:
            print(f"[Honeypot Callback Error] {e}")


# ─── Honeypot Endpoints ──────────────────────────────────────────────

ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel — Internal Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #16213e 0%, #0f3460 100%); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; color: #e94560; }
        .header .badge { background: #e94560; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; }
        .container { max-width: 600px; margin: 80px auto; padding: 40px; }
        .login-box { background: #16213e; border-radius: 12px; padding: 40px; border: 1px solid #0f3460; }
        .login-box h2 { text-align: center; margin-bottom: 30px; color: #e94560; font-size: 22px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #a0a0b0; font-size: 14px; }
        .form-group input { width: 100%; padding: 12px 16px; background: #0f3460; border: 1px solid #1a1a4e; border-radius: 8px; color: white; font-size: 14px; }
        .form-group input:focus { border-color: #e94560; outline: none; }
        .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #e94560, #c23152); border: none; color: white; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: all 0.3s; }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 15px rgba(233, 69, 96, 0.4); }
        .footer { text-align: center; margin-top: 20px; color: #555; font-size: 12px; }
        .alert { background: #2d1b1b; border: 1px solid #e94560; padding: 12px; border-radius: 8px; margin-bottom: 20px; color: #e94560; font-size: 13px; display: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Admin Control Panel</h1>
        <span class="badge">INTERNAL USE ONLY</span>
    </div>
    <div class="container">
        <div class="login-box">
            <h2>Administrator Login</h2>
            <div class="alert" id="alert">Invalid credentials. This attempt has been logged.</div>
            <form method="POST" action="/admin" id="loginForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" id="username" placeholder="admin@company.com" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" id="password" placeholder="Enter password" required>
                </div>
                <div class="form-group">
                    <label>2FA Code</label>
                    <input type="text" name="totp" placeholder="6-digit code" maxlength="6">
                </div>
                <button type="submit" class="btn">Sign In</button>
            </form>
            <div class="footer">
                <p>Authorized personnel only. All access is monitored and logged.</p>
                <p style="margin-top: 8px;">v3.8.2 | Internal Systems &copy; 2026</p>
            </div>
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            var alert = document.getElementById('alert');
            alert.style.display = 'block';
            // Still submit the form data to the server for logging
            fetch('/admin', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                })
            });
        });
    </script>
</body>
</html>
"""


@honeypot_bp.route("/admin", methods=["GET", "POST"])
def fake_admin():
    """Fake admin panel — attracts unauthorized access attempts."""
    if request.method == "POST":
        _log_interaction("/admin", "LOGIN_ATTEMPT")
        return jsonify({"error": "Invalid credentials", "locked": True}), 401
    else:
        _log_interaction("/admin", "PAGE_VIEW")
        return render_template_string(ADMIN_PANEL_HTML)


@honeypot_bp.route("/api/users", methods=["GET"])
@honeypot_bp.route("/api/users/<int:user_id>", methods=["GET"])
def fake_users(user_id=None):
    """Fake user API — returns synthetic user data."""
    _log_interaction("/api/users", "DATA_ACCESS")

    # Intentional delay to slow down scrapers
    time.sleep(random.uniform(0.5, 1.5))

    if user_id:
        user = _fake_user()
        user["id"] = user_id
        return jsonify({"status": "success", "data": user})

    users = [_fake_user() for _ in range(random.randint(5, 15))]
    return jsonify({
        "status": "success",
        "data": users,
        "pagination": {"page": 1, "total": random.randint(100, 500), "per_page": 20}
    })


@honeypot_bp.route("/api/config", methods=["GET"])
def fake_config():
    """Fake configuration endpoint — leaks synthetic credentials."""
    _log_interaction("/api/config", "CONFIG_ACCESS")
    time.sleep(random.uniform(0.3, 1.0))
    return jsonify({"status": "success", "config": _fake_config()})


@honeypot_bp.route("/api/keys", methods=["GET"])
def fake_keys():
    """Fake API keys endpoint."""
    _log_interaction("/api/keys", "KEY_ACCESS")
    time.sleep(random.uniform(0.5, 1.0))
    keys = {
        "production": {
            "primary": _fake_api_key(),
            "secondary": _fake_api_key(),
            "webhook_secret": ''.join(random.choices(string.ascii_letters + string.digits, k=40)),
        },
        "staging": {
            "primary": _fake_api_key(),
        },
        "created_at": "2026-01-15T10:30:00Z",
        "rotated_at": "2026-03-28T14:22:00Z",
    }
    return jsonify({"status": "success", "api_keys": keys})


@honeypot_bp.route("/api/database", methods=["GET"])
def fake_database():
    """Fake database dump endpoint."""
    _log_interaction("/api/database", "DATABASE_ACCESS")
    time.sleep(random.uniform(1.0, 2.0))
    return jsonify({
        "status": "success",
        "tables": ["users", "payments", "sessions", "api_keys", "audit_log"],
        "total_records": random.randint(10000, 500000),
        "last_backup": "2026-04-06T02:00:00Z",
        "connection_string": f"postgresql://admin:{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}@db.internal:5432/production"
    })


@honeypot_bp.route("/.env", methods=["GET"])
def fake_env():
    """Fake .env file — a classic target for attackers."""
    _log_interaction("/.env", "ENV_ACCESS")
    return _fake_env(), 200, {"Content-Type": "text/plain"}


@honeypot_bp.route("/wp-admin", methods=["GET", "POST"])
@honeypot_bp.route("/wp-login.php", methods=["GET", "POST"])
def fake_wordpress():
    """Fake WordPress admin — attracts automated scanners."""
    _log_interaction("/wp-admin", "SCANNER_ACCESS")
    if request.method == "POST":
        return jsonify({"error": "Invalid credentials"}), 401
    return render_template_string("""
    <html><head><title>WordPress — Log In</title></head>
    <body style="background:#f0f0f1; font-family:sans-serif;">
    <div style="max-width:320px; margin:100px auto; background:white; padding:26px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.13);">
        <h1 style="text-align:center; margin-bottom:20px;">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40" fill="#0073aa"><circle cx="12" cy="12" r="12"/></svg>
        </h1>
        <form method="POST">
            <p><label>Username or Email<br><input type="text" name="log" style="width:100%;padding:5px;margin-top:4px;"></label></p>
            <p><label>Password<br><input type="password" name="pwd" style="width:100%;padding:5px;margin-top:4px;"></label></p>
            <p><input type="submit" value="Log In" style="background:#0073aa;color:white;border:none;padding:8px 20px;cursor:pointer;border-radius:3px;"></p>
        </form>
    </div></body></html>
    """)


@honeypot_bp.route("/debug", methods=["GET"])
def fake_debug():
    """Fake debug console."""
    _log_interaction("/debug", "DEBUG_ACCESS")
    return jsonify({
        "debug_mode": True,
        "server": "prod-web-03.company.net",
        "uptime": f"{random.randint(10, 90)} days",
        "memory_usage": f"{random.randint(40, 85)}%",
        "active_connections": random.randint(50, 300),
        "database_pool": {"active": random.randint(5, 20), "idle": random.randint(2, 10), "max": 50},
        "cache_hit_rate": f"{random.uniform(85, 99):.1f}%",
        "error_rate": f"{random.uniform(0.01, 0.5):.2f}%",
    })


@honeypot_bp.route("/api/secrets", methods=["GET"])
def fake_secrets():
    """Fake secrets vault."""
    _log_interaction("/api/secrets", "SECRETS_ACCESS")
    time.sleep(random.uniform(0.5, 1.0))
    return jsonify({
        "vault": "production",
        "secrets": {
            "stripe_secret_key": "sk_live_" + ''.join(random.choices(string.ascii_letters + string.digits, k=24)),
            "twilio_auth_token": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            "sendgrid_api_key": "SG." + ''.join(random.choices(string.ascii_letters + string.digits, k=22)) + "." + ''.join(random.choices(string.ascii_letters + string.digits, k=43)),
            "firebase_admin_key": json.dumps({"type": "service_account", "project_id": "company-prod"}),
        }
    })


# ─── Honeypot Analysis ───────────────────────────────────────────────

class HoneypotAnalyzer:
    """Analyze honeypot interaction patterns."""

    @staticmethod
    def get_attacker_profiles():
        """Analyze honeypot logs to build attacker profiles."""
        logs = get_honeypot_logs(limit=500)
        profiles = {}

        for log in logs:
            ip = log["ip_address"]
            if ip not in profiles:
                profiles[ip] = {
                    "ip": ip,
                    "interactions": 0,
                    "endpoints_targeted": set(),
                    "methods_used": set(),
                    "first_seen": log["timestamp"],
                    "last_seen": log["timestamp"],
                    "interaction_types": set(),
                    "payloads_submitted": 0,
                }

            p = profiles[ip]
            p["interactions"] += 1
            p["endpoints_targeted"].add(log["endpoint"])
            p["methods_used"].add(log["method"])
            p["last_seen"] = max(p["last_seen"], log["timestamp"])
            p["first_seen"] = min(p["first_seen"], log["timestamp"])
            p["interaction_types"].add(log.get("interaction_type", "UNKNOWN"))
            if log.get("payload"):
                p["payloads_submitted"] += 1

        # Convert sets to lists for JSON serialization
        for ip in profiles:
            profiles[ip]["endpoints_targeted"] = list(profiles[ip]["endpoints_targeted"])
            profiles[ip]["methods_used"] = list(profiles[ip]["methods_used"])
            profiles[ip]["interaction_types"] = list(profiles[ip]["interaction_types"])

        return list(profiles.values())

    @staticmethod
    def get_summary():
        """Get honeypot activity summary."""
        logs = get_honeypot_logs(limit=1000)
        if not logs:
            return {"total_interactions": 0, "unique_attackers": 0, "most_targeted": []}

        from collections import Counter
        ips = Counter(l["ip_address"] for l in logs)
        endpoints = Counter(l["endpoint"] for l in logs)

        return {
            "total_interactions": len(logs),
            "unique_attackers": len(ips),
            "most_targeted": endpoints.most_common(5),
            "top_attackers": ips.most_common(5),
            "recent_activity": logs[:10],
        }
