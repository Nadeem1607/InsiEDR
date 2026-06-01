from __future__ import annotations

import ast
import builtins
import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_FILES = [
    PROJECT_ROOT / "agent/collectors/short-Term_EDR_Feature.py",
    PROJECT_ROOT / "agent/collectors/devices_feature.py",
    PROJECT_ROOT / "agent/collectors/file_feature.py",
    PROJECT_ROOT / "agent/collectors/http_feature.py",
    PROJECT_ROOT / "agent/collectors/logon.py",
    PROJECT_ROOT / "agent/collectors/network_monitor.py",
]

AGENT_ENTRYPOINT_NAMES = {
    "collect",
    "collect_features",
    "collect_file_features",
    "collect_http_features",
    "collect_raw_usb_telemetry",
    "derive_features",
    "compute_features",
}

DB_CALL_NAMES = {
    "connect",
    "get_connection",
    "get_db_connection",
    "_pg_connect",
    "ensure_table",
    "ensure_schema",
    "insert_records",
    "insert_features",
    "insert_features_batch",
    "batch_insert",
    "validate_db",
    "execute_values",
    "execute_batch",
}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def test_agent_collector_entrypoints_do_not_call_database_paths():
    violations = []
    for path in COLLECTOR_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in AGENT_ENTRYPOINT_NAMES:
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and _call_name(child.func) in DB_CALL_NAMES:
                        violations.append((path.name, node.name, child.lineno, _call_name(child.func)))

    assert violations == []


def test_legacy_collectors_import_without_postgresql_installed(monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "psycopg2" or name.startswith("psycopg2."):
            raise ImportError("blocked PostgreSQL driver")
        return real_import(name, *args, **kwargs)

    import platform

    for index, path in enumerate(COLLECTOR_FILES):
        with monkeypatch.context() as module_patch:
            module_patch.setattr(builtins, "__import__", guarded_import)
            if path.name in {"short-Term_EDR_Feature.py", "devices_feature.py"}:
                module_patch.setattr(platform, "system", lambda: "Linux")
            if path.name == "logon.py":
                module_patch.setattr(sys, "platform", "linux")

            spec = importlib.util.spec_from_file_location(f"collector_no_pg_{index}", path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"collector_no_pg_{index}"] = module
            spec.loader.exec_module(module)

            assert callable(getattr(module, "collect_features", None))
