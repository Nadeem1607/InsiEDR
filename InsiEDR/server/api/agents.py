from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("agents", __name__, url_prefix="/api")


@bp.route("/agents", methods=["GET"])
def get_agents():
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured", "agents": []}), 503
	limit = int(request.args.get("limit", 100))
	offset = int(request.args.get("offset", 0))
	return jsonify({"ok": True, "agents": storage.list_agents(limit=limit, offset=offset)})
