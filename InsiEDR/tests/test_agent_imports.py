from __future__ import annotations

import builtins
import importlib
import importlib.util
import sys
from pathlib import Path

from agent.collectors import discover_collectors


PROJECT_ROOT = Path(__file__).resolve().parents[1]


REQUIRED_FILES = [
    "agent/agent.py",
    "agent/config.py",
    "agent/payload_builder.py",
    "agent/transport.py",
    "agent/crypto/aesgcm.py",
    "agent/crypto/fernet_compat.py",
    "agent/collectors/__init__.py",
    "agent/collectors/base.py",
    "agent/collectors/file_scanner.py",
    "agent/collectors/browser_history.py",
    "agent/collectors/usb_monitor.py",
    "agent/collectors/session_monitor.py",
    "agent/collectors/network_monitor.py",
    "agent/queue/local_queue.py",
    "shared/protocol.py",
    "shared/crypto_utils.py",
]


REQUIRED_MODULES = [
    "agent.agent",
    "agent.config",
    "agent.payload_builder",
    "agent.transport",
    "agent.crypto.aesgcm",
    "agent.crypto.fernet_compat",
    "agent.collectors",
    "agent.collectors.base",
    "agent.collectors.file_scanner",
    "agent.collectors.browser_history",
    "agent.collectors.usb_monitor",
    "agent.collectors.session_monitor",
    "agent.collectors.network_monitor",
    "agent.queue.local_queue",
    "shared.protocol",
    "shared.crypto_utils",
]


def test_required_agent_files_exist():
    missing = [path for path in REQUIRED_FILES if not (PROJECT_ROOT / path).is_file()]

    assert missing == []


def test_required_agent_modules_are_importable():
    imported = [importlib.import_module(name) for name in REQUIRED_MODULES]

    assert len(imported) == len(REQUIRED_MODULES)


def test_agent_requirements_do_not_install_postgresql_driver():
    requirements = (PROJECT_ROOT / "agent/requirements_agent.txt").read_text(encoding="utf-8").lower()

    assert "psycopg2" not in requirements
    assert "postgres" not in requirements


def test_agent_runtime_code_does_not_import_postgresql_driver():
    runtime_text = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (PROJECT_ROOT / "agent", PROJECT_ROOT / "shared")
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    ).lower()

    assert "psycopg2" not in runtime_text


def test_legacy_collectors_import_without_postgresql_driver(monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "psycopg2" or name.startswith("psycopg2."):
            raise ImportError("blocked PostgreSQL driver")
        return real_import(name, *args, **kwargs)

    import platform

    collector_files = [
        "agent/collectors/short-Term_EDR_Feature.py",
        "agent/collectors/devices_feature.py",
        "agent/collectors/file_feature.py",
        "agent/collectors/http_feature.py",
        "agent/collectors/logon.py",
    ]

    for index, relative_path in enumerate(collector_files):
        with monkeypatch.context() as module_patch:
            module_patch.setattr(builtins, "__import__", guarded_import)
            if relative_path.endswith(("short-Term_EDR_Feature.py", "devices_feature.py")):
                module_patch.setattr(platform, "system", lambda: "Linux")
            if relative_path.endswith("logon.py"):
                module_patch.setattr(sys, "platform", "linux")

            module_name = f"test_no_postgres_collector_{index}"
            spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / relative_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

        assert callable(getattr(module, "collect_features", None))


def test_default_collectors_are_discoverable_without_running_platform_telemetry():
    collectors = discover_collectors(hostname="qa-host")

    assert [collector.name for collector in collectors] == [
        "short-term-edr",
        "computed-meta-features",
        "devices-feature",
        "file-feature",
        "http-feature",
        "logon",
    ]
    assert all(callable(getattr(collector, "collect", None)) for collector in collectors)
