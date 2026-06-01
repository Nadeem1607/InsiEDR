from __future__ import annotations

from typing import Any


class StorageError(RuntimeError):
    pass


class BaseStorage:
    def store_raw_payload(self, envelope: dict[str, Any], decrypted_payload: dict[str, Any]) -> None:
        raise NotImplementedError()

    def get_payload(self, payload_id: str) -> dict[str, Any] | None:
        raise NotImplementedError()

    def ensure_migrations(self) -> None:
        raise NotImplementedError()

    def list_agents(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_logs(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def list_baselines(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError()

    def get_stats(self) -> dict[str, Any]:
        raise NotImplementedError()

    def save_baseline(self, baseline: dict[str, Any]) -> None:
        raise NotImplementedError()

    def load_baseline(self, username: str) -> dict[str, Any] | None:
        raise NotImplementedError()
