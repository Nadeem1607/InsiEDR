from __future__ import annotations

import importlib.util
import logging
import re
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping


log = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if hasattr(value, "adapted"):
        return json_safe(getattr(value, "adapted"))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported collector payload value type: {type(value).__name__}")


@dataclass
class CollectorResult:
    collector: str
    collected_at: str
    hostname: str
    status: str
    payload: dict[str, Any] | None = None
    error: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "collector": self.collector,
            "collected_at": self.collected_at,
            "hostname": self.hostname,
            "status": self.status,
        }
        if self.payload is not None:
            data["payload"] = json_safe(self.payload)
        if self.error is not None:
            data["error"] = self.error
        return data


class BaseCollector(ABC):
    name = "base"
    source_filename = ""

    def __init__(self, *, hostname: str | None = None) -> None:
        self.hostname = hostname or socket.gethostname()

    @abstractmethod
    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Collect features and return a wrapped result."""

    def success(self, payload: Mapping[str, Any]) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            collected_at=utc_now_iso(),
            hostname=self.hostname,
            status="success",
            payload=dict(json_safe(payload)),
        )

    def failed(self, exc: BaseException | str) -> CollectorResult:
        if isinstance(exc, BaseException):
            error = {"type": exc.__class__.__name__, "message": str(exc)}
        else:
            error = {"type": "CollectorError", "message": exc}
        return CollectorResult(
            collector=self.name,
            collected_at=utc_now_iso(),
            hostname=self.hostname,
            status="failed",
            error=error,
        )


def _module_name_from_path(path: Path) -> str:
    safe = re.sub(r"\W+", "_", path.stem).strip("_").lower()
    return f"insiedr_collector_{safe}"


class PythonModuleCollector(BaseCollector):
    """Adapter for existing collector scripts, including hyphenated filenames."""

    def __init__(
        self,
        *,
        name: str,
        path: Path,
        hostname: str | None = None,
        function_names: tuple[str, ...] = ("collect_features", "collect"),
        fallback: Callable[[ModuleType], Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__(hostname=hostname)
        self.name = name
        self.source_filename = path.name
        self.path = path
        self.function_names = function_names
        self.fallback = fallback

    def _load_module(self) -> ModuleType:
        if not self.path.is_file():
            raise FileNotFoundError(str(self.path))
        spec = importlib.util.spec_from_file_location(_module_name_from_path(self.path), self.path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build import spec for {self.path.name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(spec.name, None)
            raise
        return module

    def _call_module(self, module: ModuleType) -> Mapping[str, Any]:
        for function_name in self.function_names:
            candidate = getattr(module, function_name, None)
            if callable(candidate):
                result = candidate()
                if isinstance(result, Mapping):
                    return result
                if isinstance(result, list):
                    return {"items": result}
                raise TypeError(
                    f"collector {self.source_filename} returned unsupported payload type: "
                    f"{type(result).__name__}"
                )
        if self.fallback is not None:
            return self.fallback(module)
        raise AttributeError(f"collector {self.source_filename} has no callable collection entry point")

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        del context
        try:
            module = self._load_module()
            payload = self._call_module(module)
            return self.success(payload)
        except BaseException as exc:
            log.warning("collector %s failed: %s", self.name, exc)
            return self.failed(exc)


class ComputedMetaFeatureCollector(BaseCollector):
    name = "computed-meta-features"
    source_filename = "computed_Meta-Features"

    def __init__(self, *, path: Path, hostname: str | None = None) -> None:
        super().__init__(hostname=hostname)
        self.path = path

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        del context
        if not self.path.exists():
            return self.failed(f"spec file missing: {self.path.name}")
        return self.success(
            {
                "spec_file": self.path.name,
                "status": "server_deferred",
                "server_deferred_features": [
                    "daily_files_to_removable_7d_sum",
                ],
                "reason": "The endpoint emits collection features only; long-window derivations are computed from received telemetry outside the agent.",
            }
        )
