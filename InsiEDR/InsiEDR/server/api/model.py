from flask import Blueprint, current_app, jsonify, request
from server.detectors.random_forest_detector import RandomForestDetector

bp = Blueprint("model", __name__, url_prefix="/api/model")

@bp.route("/recalibrate", methods=["POST"])
def recalibrate():
    """
    Forces the Random Forest model to recalibrate (retrain) using 
    the latest historical data in PostgreSQL.
    """
    storage = current_app.extensions.get("insiedr_storage")
    if not storage:
        return jsonify({"ok": False, "error": "Storage backend not available"}), 500

    try:
        # Default to 30 days of data, or accept days param from JSON
        days = 30
        if request.is_json:
            days = request.json.get("days", 30)

        from server.detectors.isolation_forest_detector import IsolationForestDetector
        
        rf_detector = RandomForestDetector()
        rf_result = rf_detector.train_model(storage, days=days)
        
        if_detector = IsolationForestDetector()
        if_result = if_detector.train_model(storage, days=days)
        
        if rf_result.get("status") == "success" and if_result.get("status") == "success":
            return jsonify({
                "ok": True, 
                "result": {
                    "random_forest": rf_result,
                    "isolation_forest": if_result
                }
            }), 200
        else:
            return jsonify({"ok": False, "error": f"RF: {rf_result.get('message')}, IF: {if_result.get('message')}"}), 400
            
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
