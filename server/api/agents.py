from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("agents", __name__, url_prefix="/api")


@bp.route("/agents", methods=["GET"])
@bp.route("/v1/agents", methods=["GET"])
def get_agents():
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured", "agents": []}), 503
	limit = int(request.args.get("limit", 100))
	offset = int(request.args.get("offset", 0))
	return jsonify({"ok": True, "agents": storage.list_agents(limit=limit, offset=offset)})

@bp.route("/agents/tamper-alerts", methods=["GET"])
def get_tamper_alerts():
	"""Returns recent risk events where tamper_detector fired."""
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured", "alerts": []}), 503

	limit = int(request.args.get("limit", 50))
	try:
		# Fetch recent risk events (a larger window since tamper events might be rare)
		risk_events = storage.list_risk_events(limit=500, offset=0)

		tamper_alerts = []
		for ev in risk_events:
			try:
				signals = ev.get("correlated_signals_json")
				if isinstance(signals, str):
					import json
					signals = json.loads(signals)
				elif signals is None:
					signals = {}

				# Check if tamper detector fired
				if signals.get("tamper_detector", {}).get("is_anomaly") is True:
					# Patch risk level for consistency with UI expectations
					level = (ev.get("risk_level") or "").upper()
					if not level or level in ["NONE", "INFO"]:
						score = float(ev.get("risk_score") or 0.0)
						if score >= 85.0: level = "CRITICAL"
						elif score >= 60.0: level = "HIGH"
						elif score >= 35.0: level = "MEDIUM"
						else: level = "LOW"
					ev["risk_level"] = level

					tamper_alerts.append(ev)
			except Exception:
				continue

			if len(tamper_alerts) >= limit:
				break

		return jsonify({"ok": True, "alerts": tamper_alerts})
	except Exception as e:
		return jsonify({"ok": False, "error": str(e), "alerts": []}), 500
