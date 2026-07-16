import os
import pytest

from server.storage.postgres_storage import PostgresStorage


def _dsn_from_env():
    # Support both INSIEDR_DATABASE_DSN and DATABASE_DSN
    return os.environ.get("INSIEDR_DATABASE_DSN") or os.environ.get("DATABASE_DSN")


@pytest.mark.skipif(not _dsn_from_env(), reason="Postgres DSN not configured")
def test_postgres_storage_migrations_and_stats():
    dsn = _dsn_from_env()
    storage = PostgresStorage(dsn=dsn)
    # This will run migrations against the provided DSN. Requires a fresh or disposable DB.
    storage.ensure_migrations()
    stats = storage.get_stats()
    assert isinstance(stats, dict)
    assert stats.get("ok", True) is True
