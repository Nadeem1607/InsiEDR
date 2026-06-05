from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from server.plugin_registry import registry
from server.model_bridge import bridge as model_bridge

bp = Blueprint("health", __name__, url_prefix="/api")


@bp.route("/health", methods=["GET"])
def health():
    storage = current_app.extensions.get("insiedr_storage")
    database = "not_configured"
    if storage is not None:
        try:
            storage.get_stats()
            database = "ok"
        except Exception:
            database = "error"
    schemes = registry.schemes()
    crypto = "ok" if "aes-256-gcm" in schemes else "missing_aes_key"
    plaintext = "enabled" if "plaintext" in schemes else "disabled"
    model_readiness = model_bridge.readiness()
    if model_readiness["ready"]:
        model_pipeline = "ready"
    elif model_readiness["missing_artifacts"]:
        model_pipeline = "missing_artifacts"
    elif model_readiness["missing_dependencies"]:
        model_pipeline = "missing_dependencies"
    else:
        model_pipeline = "disabled"
    return jsonify(
        {
            "ok": database != "error" and crypto == "ok",
            "database": database,
            "crypto": crypto,
            "crypto_schemes": schemes,
            "plaintext_crypto": plaintext,
            "migrations": "ok" if storage is not None else "not_configured",
            "model_pipeline": model_pipeline,
            "model_missing_artifacts": model_readiness["missing_artifacts"],
            "model_missing_dependencies": model_readiness["missing_dependencies"],
            "auth": "not_configured",
        }
    )
