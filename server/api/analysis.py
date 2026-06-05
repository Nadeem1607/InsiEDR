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
