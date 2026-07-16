from __future__ import annotations

from flask import Blueprint, current_app, jsonify

bp = Blueprint("stats", __name__, url_prefix="/api")


@bp.route("/stats", methods=["GET"])
def get_stats():
	storage = current_app.extensions.get("insiedr_storage")
	if storage is None:
		return jsonify({"ok": False, "error": "storage is not configured"}), 503
	return jsonify(storage.get_stats())
