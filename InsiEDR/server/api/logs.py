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
    import inspect
    sig = inspect.signature(storage.list_logs)
    
    # Only pass filters that the storage adapter explicitly accepts, or if it accepts **kwargs
    accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    valid_filters = {
        k: v for k, v in filters.items() 
        if v and (accepts_kwargs or k in sig.parameters)
    }
    
    logs = storage.list_logs(limit=limit, offset=offset, **valid_filters)
    return jsonify({"ok": True, "logs": logs})

@bp.route("/telemetry", methods=["GET"])
def get_telemetry():
    storage = current_app.extensions.get("insiedr_storage")
    if storage is None:
        return jsonify({"ok": False, "error": "storage is not configured", "telemetry": []}), 503
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    collector = request.args.get("collector")
    username = request.args.get("username")
    try:
        telemetry = storage.list_collector_results(limit=limit, offset=offset, collector=collector, username=username)
    except AttributeError:
        return jsonify({"ok": False, "error": "storage method not implemented", "telemetry": []}), 501
    return jsonify({"ok": True, "logs": telemetry})
