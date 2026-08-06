from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("anomalies", __name__, url_prefix="/api")


@bp.route("/anomalies", methods=["GET"])
def get_anomalies():
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured", "anomalies": []}), 503
	limit = int(request.args.get("limit", 100))
	offset = int(request.args.get("offset", 0))
	risk_events = []
	list_risk_events = getattr(storage, "list_risk_events", None)
	if callable(list_risk_events):
		risk_events = list_risk_events(limit=limit, offset=offset)
	return jsonify({"ok": True, "anomalies": storage.list_anomalies(limit=limit, offset=offset), "risk_events": risk_events})
