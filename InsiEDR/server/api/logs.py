from __future__ import annotations

from flask import Blueprint, current_app, request, jsonify

from server.api.ingest import process_encrypted_request, IngestError

bp = Blueprint("logs", __name__, url_prefix="/api")


@bp.route("/logs", methods=["POST"])
def post_logs():
    try:
        status_code, body = process_encrypted_request(request)
        return (jsonify(body), status_code)
    except IngestError as exc:
        return (jsonify({"ok": False, "error": str(exc)}), exc.status_code)


@bp.route("/logs", methods=["GET"])
def get_logs():
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured", "logs": []}), 503
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    filters = {
        "agent_id": request.args.get("agent_id"),
        "hostname": request.args.get("hostname"),
        "username": request.args.get("username"),
        "collector": request.args.get("collector"),
        "status": request.args.get("status"),
        "start_time": request.args.get("start_time"),
        "end_time": request.args.get("end_time"),
    }
    try:
        logs = storage.list_logs(limit=limit, offset=offset, **{k: v for k, v in filters.items() if v})
    except TypeError:
        logs = storage.list_logs(limit=limit, offset=offset)
    return jsonify({"ok": True, "logs": logs})

@bp.route("/telemetry", methods=["GET"])
def get_telemetry():
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured", "telemetry": []}), 503
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    collector = request.args.get("collector")
    try:
        telemetry = storage.list_collector_results(limit=limit, offset=offset, collector=collector)
    except AttributeError:
        return jsonify({"ok": False, "error": "storage method not implemented", "telemetry": []}), 501
    return jsonify({"ok": True, "logs": telemetry})
