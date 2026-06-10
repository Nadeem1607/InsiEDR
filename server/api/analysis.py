from __future__ import annotations

from flask import Blueprint, current_app, request, jsonify

bp = Blueprint("analysis", __name__, url_prefix="/api")


@bp.route("/pc-status", methods=["GET"])
def get_pc_status():
    """Returns PC online/offline status"""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503
    
    hours = int(request.args.get("hours", 24))
    try:
        status = storage.get_pc_status(hours_since_online=hours)
        return jsonify({"ok": True, **status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/user-collectors/<username>", methods=["GET"])
def get_user_collectors(username: str):
    """Returns all collectors and their latest data for a user"""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503
    
    try:
        collectors = storage.get_user_collectors(username)
        return jsonify({"ok": True, "username": username, "collectors": collectors})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/user-risk-scores/<username>", methods=["GET"])
def get_user_risk_scores(username: str):
    """Returns historical risk scores for a user"""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503
    
    limit = int(request.args.get("limit", 30))
    try:
        risk_scores = storage.get_user_risk_scores(username, limit=limit)
        return jsonify({"ok": True, "username": username, "risk_scores": risk_scores})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/user-predictions/<username>", methods=["GET"])
def get_user_predictions(username: str):
    """Returns latest model predictions for a user"""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503
    
    try:
        predictions = storage.get_user_predictions(username)
        if predictions is None:
            return jsonify({"ok": True, "username": username, "predictions": None, "message": "No predictions available"}), 200
        return jsonify({"ok": True, "username": username, "predictions": predictions})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/user-analysis/<username>", methods=["GET"])
def get_user_analysis(username: str):
    """Combined endpoint: returns collectors, risk scores, and predictions for a user"""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503
    
    try:
        collectors = storage.get_user_collectors(username)
        risk_scores = storage.get_user_risk_scores(username, limit=30)
        predictions = storage.get_user_predictions(username)
        
        return jsonify({
            "ok": True,
            "username": username,
            "collectors": collectors,
            "risk_scores": risk_scores,
            "predictions": predictions
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/dashboard-summary", methods=["GET"])
def dashboard_summary():
    """Aggregated dashboard data in a single call."""
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured"}), 503

    try:
        pc_status = storage.get_pc_status(hours_since_online=24)
        risk_events = storage.list_risk_events(limit=200, offset=0)
        anomalies = storage.list_anomalies(limit=100, offset=0)
        agents = storage.list_agents(limit=500, offset=0)
        stats = storage.get_stats()

        # Pre-compute risk category counts from latest risk event per user
        user_latest_risk: dict[str, dict] = {}
        for event in risk_events:
            user = event.get("username") or "unknown"
            if user not in user_latest_risk:
                user_latest_risk[user] = event

        high_count = sum(1 for e in user_latest_risk.values() if (e.get("risk_level") or "").upper() in ("HIGH", "CRITICAL"))
        medium_count = sum(1 for e in user_latest_risk.values() if (e.get("risk_level") or "").upper() == "MEDIUM")
        low_count = sum(1 for e in user_latest_risk.values() if (e.get("risk_level") or "").upper() == "LOW")

        # Build unique user list from agents table
        users = sorted({str(a.get("username_last_seen") or "") for a in agents if a.get("username_last_seen")})

        # Collector health: latest status per collector type
        collector_health: dict[str, dict] = {}
        for agent in agents:
            hostname = agent.get("hostname")
            last_seen = agent.get("last_seen_at")
            if hostname and hostname not in collector_health:
                collector_health[hostname] = {"last_seen": last_seen, "status": agent.get("status", "unknown")}

        return jsonify({
            "ok": True,
            "pc_status": pc_status,
            "risk_counts": {"high": high_count, "medium": medium_count, "low": low_count},
            "risk_events": risk_events[:50],
            "anomalies": anomalies[:50],
            "agents": agents,
            "users": users,
            "stats": stats,
            "total_risk_events": len(risk_events),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

