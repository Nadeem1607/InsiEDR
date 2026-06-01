from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .base import BaseCollector, CollectorResult, ComputedMetaFeatureCollector, PythonModuleCollector


log = logging.getLogger(__name__)

COLLECTOR_DIR = Path(__file__).resolve().parent
DEFAULT_DISCOVERY_COLLECTORS = (
    "short-term-edr",
    "computed-meta-features",
    "devices-feature",
    "file-feature",
    "http-feature",
    "logon",
)


def _short_term_fallback(module) -> Mapping[str, Any]:
    raw_events = module.collect_auth_events(module.CONFIG["BASELINE_SECONDS"])
    return module.compute_features(raw_events)


def _device_fallback(module) -> Mapping[str, Any]:
    return module.derive_features(module.collect_raw_usb_telemetry())


def _file_fallback(module) -> Mapping[str, Any]:
    return module.collect_file_features()


def _http_fallback(module) -> Mapping[str, Any]:
    return module.collect_http_features()


def _logon_fallback(module) -> Mapping[str, Any]:
    target = datetime.now()
    day_start, day_end = module._build_time_filter(target)
    events = module.query_security_events([4624, 4634, 4647, 4625], day_start, day_end)
    return module.derive_features(events, target)


COLLECTOR_SPECS = {
    "short-term-edr": {
        "filename": "short-Term_EDR_Feature.py",
        "fallback": _short_term_fallback,
        "aliases": {"short-term-edr", "short_term_edr_feature", "short-Term_EDR_Feature.py"},
    },
    "computed-meta-features": {
        "filename": "computed_Meta-Features",
        "aliases": {"computed-meta-features", "computed_meta_features", "computed_Meta-Features"},
    },
    "devices-feature": {
        "filename": "devices_feature.py",
        "fallback": _device_fallback,
        "aliases": {"devices-feature", "devices_feature", "devices_feature.py"},
    },
    "file-feature": {
        "filename": "file_feature.py",
        "fallback": _file_fallback,
        "aliases": {"file-feature", "file_feature", "file_feature.py"},
    },
    "http-feature": {
        "filename": "http_feature.py",
        "fallback": _http_fallback,
        "aliases": {"http-feature", "http_feature", "http_feature.py"},
    },
    "logon": {
        "filename": "logon.py",
        "fallback": _logon_fallback,
        "aliases": {"logon", "logon.py"},
    },
    "network-monitor": {
        "filename": "network_monitor.py",
        "aliases": {"network-monitor", "network_monitor", "network_monitor.py"},
    },
}


def _canonical_name(name: str) -> str:
    normalized = name.strip()
    for canonical, spec in COLLECTOR_SPECS.items():
        if normalized == canonical or normalized in spec["aliases"]:
            return canonical
    return normalized


def discover_collectors(
    enabled: Iterable[str] | None = None,
    *,
    collectors_dir: Path | None = None,
    hostname: str | None = None,
) -> list[BaseCollector]:
    base_dir = collectors_dir or COLLECTOR_DIR
    requested = [_canonical_name(item) for item in (enabled or DEFAULT_DISCOVERY_COLLECTORS)]
    collectors: list[BaseCollector] = []

    for name in requested:
        spec = COLLECTOR_SPECS.get(name)
        if spec is None:
            log.warning("unknown collector configured: %s", name)
            continue
        path = base_dir / spec["filename"]
        if name == "computed-meta-features":
            collectors.append(ComputedMetaFeatureCollector(path=path, hostname=hostname))
        else:
            collectors.append(
                PythonModuleCollector(
                    name=name,
                    path=path,
                    hostname=hostname,
                    fallback=spec.get("fallback"),
                )
            )
    return collectors


def run_collectors(collectors: Iterable[BaseCollector]) -> list[CollectorResult]:
    results: list[CollectorResult] = []
    context: dict[str, Any] = {"results": results}
    for collector in collectors:
        try:
            result = collector.collect(context)
        except BaseException as exc:
            log.exception("collector wrapper raised unexpectedly: %s", collector.name)
            result = collector.failed(exc)
        results.append(result)
    return results


__all__ = [
    "BaseCollector",
    "CollectorResult",
    "discover_collectors",
    "run_collectors",
]
