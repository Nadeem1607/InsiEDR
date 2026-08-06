from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("baseline", __name__, url_prefix="/api")


@bp.route("/baseline/<username>", methods=["GET"])
def get_baseline(username: str):
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured", "baseline": []}), 503
	limit = int(request.args.get("limit", 100))
	offset = int(request.args.get("offset", 0))
	items = [row for row in storage.list_baselines(limit=limit, offset=offset) if row.get("username") == username]
	return jsonify({"ok": True, "username": username, "baseline": items})
