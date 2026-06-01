"""
dashboard.py - Dashboard API Blueprint
Serves the monitoring dashboard and provides REST API endpoints
for real-time data access.
"""

from flask import Blueprint, render_template, jsonify, request
from database import (
    get_dashboard_stats, get_all_risk_scores, get_system_events,
    get_blocked_ips, get_honeypot_logs, get_active_rules, get_healing_log
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
def dashboard_page():
    """Serve the main monitoring dashboard."""
    return render_template("dashboard.html")


# ─── REST API Endpoints for Dashboard Data ───────────────────

@dashboard_bp.route("/api/dashboard/stats")
def api_stats():
    """Aggregated system statistics."""
    return jsonify(get_dashboard_stats())


@dashboard_bp.route("/api/dashboard/risks")
def api_risks():
    """All tracked IP risk scores."""
    return jsonify(get_all_risk_scores())


@dashboard_bp.route("/api/dashboard/events")
def api_events():
    """System events with optional type filter."""
    event_type = request.args.get("type")
    limit = int(request.args.get("limit", 100))
    return jsonify(get_system_events(limit=limit, event_type=event_type))


@dashboard_bp.route("/api/dashboard/blocked")
def api_blocked():
    """Currently blocked IPs."""
    return jsonify(get_blocked_ips())


@dashboard_bp.route("/api/dashboard/honeypot")
def api_honeypot():
    """Recent honeypot interaction logs."""
    limit = int(request.args.get("limit", 50))
    return jsonify(get_honeypot_logs(limit=limit))


@dashboard_bp.route("/api/dashboard/healing")
def api_healing():
    """Self-healing engine status."""
    from self_healing import SelfHealingEngine
    engine = SelfHealingEngine()
    active = get_active_rules()
    auto = [r for r in active if r.get("auto_generated")]
    return jsonify({
        "total_auto_rules": len(auto),
        "recent_actions": get_healing_log(10),
        "auto_rules": auto,
    })


@dashboard_bp.route("/api/dashboard/rules")
def api_rules():
    """Active defense rules."""
    return jsonify(get_active_rules())
