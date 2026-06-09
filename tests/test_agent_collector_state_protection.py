from __future__ import annotations

from datetime import datetime, timezone

from agent.collectors import file_feature, http_feature


def test_file_collector_state_hashes_raw_paths(monkeypatch, tmp_path):
    state_file = tmp_path / "file_feature_state.json"
    monkeypatch.setitem(file_feature.CONFIG, "state_file", state_file)

    file_feature._aggregate_events(
        [
            {
                "op": "CREATE",
                "path": r"C:\Users\Alice\Documents\secret-plan.txt",
                "size": 10,
                "ts": datetime.now(timezone.utc),
            }
        ]
    )

    state_text = state_file.read_text(encoding="utf-8")
    assert "secret-plan.txt" not in state_text
    assert "Alice" not in state_text
    assert "known_file_hashes" in state_text


def test_http_collector_state_hashes_raw_domains(monkeypatch, tmp_path):
    state_file = tmp_path / "http_known_domain_hashes.json"
    monkeypatch.setattr(http_feature, "HISTORICAL_DOMAIN_STATE", str(state_file))

    http_feature._save_known_domain_hashes({http_feature._hash_value("example.com")})

    state_text = state_file.read_text(encoding="utf-8")
    assert "example.com" not in state_text
    assert "known_domain_hashes" in state_text
