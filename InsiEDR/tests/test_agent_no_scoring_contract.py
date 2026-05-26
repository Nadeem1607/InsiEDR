from __future__ import annotations

import ast
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = [PROJECT_ROOT / "agent", PROJECT_ROOT / "shared"]

FORBIDDEN_IMPORT_PREFIXES = (
    "server.detectors",
    "server.baseline",
    "server.risk",
    "server.models",
    "sklearn",
    "tensorflow",
    "torch",
)

FORBIDDEN_NAME_PARTS = (
    "risk_score",
    "threat_score",
    "alert",
    "threat",
    "anomaly",
    "detector",
    "predict",
    "classify",
    "isolation_forest",
    "random_forest",
    "lstm",
    "zscore",
    "z_score",
)

ALLOWED_THRESHOLD_NAMES = (
    "timeout",
    "queue",
    "retry",
    "file",
    "large",
    "size",
    "bytes",
    "usb",
)


def _production_python_files():
    for root in PRODUCTION_ROOTS:
        yield from sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _target_names(target):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        yield target.attr
    elif isinstance(target, (ast.Tuple, ast.List)):
        for child in target.elts:
            yield from _target_names(child)


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def test_agent_production_code_does_not_import_or_define_server_side_detection_logic():
    violations = []
    for path in _production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(FORBIDDEN_IMPORT_PREFIXES):
                        violations.append((path, node.lineno, f"forbidden import {alias.name}"))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith(FORBIDDEN_IMPORT_PREFIXES):
                    violations.append((path, node.lineno, f"forbidden import {node.module}"))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                lowered = node.name.lower()
                if any(part in lowered for part in FORBIDDEN_NAME_PARTS):
                    violations.append((path, node.lineno, f"forbidden definition name {node.name}"))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    for name in _target_names(target):
                        lowered = name.lower()
                        if "threshold" in lowered and not any(part in lowered for part in ALLOWED_THRESHOLD_NAMES):
                            violations.append((path, node.lineno, f"unsafe threshold name {name}"))
                        if any(part in lowered for part in FORBIDDEN_NAME_PARTS):
                            violations.append((path, node.lineno, f"forbidden assignment name {name}"))
            elif isinstance(node, ast.Call):
                lowered = _call_name(node.func).lower()
                if lowered in {"predict", "fit_predict", "decision_function", "score_samples", "classify"}:
                    violations.append((path, node.lineno, f"forbidden call {lowered}"))

    assert violations == []


def test_short_term_edr_outputs_raw_auth_rate_features_not_burst_scores(monkeypatch):
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    path = PROJECT_ROOT / "agent/collectors/short-Term_EDR_Feature.py"
    spec = importlib.util.spec_from_file_location("short_term_contract_module", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["short_term_contract_module"] = module
    spec.loader.exec_module(module)

    now = datetime.now(timezone.utc)
    events = [
        {
            "event_id": 4624,
            "timestamp_utc": now,
            "computer": "HOST",
            "success": True,
            "target_user_name": "alice",
            "workstation_name": "WS1",
            "source_network_addr": "10.0.0.2",
            "auth_package": "Negotiate",
            "logon_type": 2,
        },
        {
            "event_id": 4625,
            "timestamp_utc": now,
            "computer": "HOST",
            "success": False,
            "target_user_name": "alice",
            "workstation_name": "WS1",
            "source_network_addr": "10.0.0.2",
            "auth_package": "Negotiate",
            "logon_type": 2,
        },
    ]

    features = module.compute_features(events)

    assert "edr_auth_burst_score" not in features
    assert "edr_auth_event_count_lookback" in features
    assert "edr_auth_events_per_minute_window" in features
    assert "edr_failed_auth_events_per_minute_window" in features
