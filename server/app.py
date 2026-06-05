from __future__ import annotations

from flask import Flask

from server.config import config
from server.api.agents import bp as agents_bp
from server.api.analysis import bp as analysis_bp
from server.api.anomalies import bp as anomalies_bp
from server.api.baseline import bp as baseline_bp
from server.api.health import bp as health_bp
from server.api.logs import bp as logs_bp
from server.api.stats import bp as stats_bp
from server.plugin_registry import registry
from server.storage.postgres_storage import PostgresStorage
from server.dashboard import bp as dashboard_bp


def create_app(*, storage=None, apply_migrations: bool = True) -> Flask:
    app = Flask(__name__)
    # register blueprints
    app.register_blueprint(agents_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(anomalies_bp)
    app.register_blueprint(baseline_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(dashboard_bp)

    # initialize plugins
    registry.initialize()
    if storage is None and config.database_dsn:
        storage = PostgresStorage(config.database_dsn)
    if storage is not None:
        app.extensions["insiedr_storage"] = storage
        ensure_migrations = getattr(storage, "ensure_migrations", None)
        if apply_migrations and callable(ensure_migrations):
            ensure_migrations()

    @app.route("/", methods=["GET"])
    def root():
        return {"ok": True, "service": "insiedr-backend"}

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000)
