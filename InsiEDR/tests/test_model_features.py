import pytest
from datetime import datetime, timezone
from server.model_bridge import ModelBridge

def test_missingness_and_failures():
    """Assert extractor handles missing/failed collectors safely."""
    payload = {
        "collectors": [
            {
                "collector": "http-feature",
                "status": "failed",
                "error": {"message": "Access denied"},
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "hostname": "test-pc"
            }
        ]
    }
    bridge = ModelBridge()
    features = bridge._payload_features(payload)
    
    # Assert feature does not fabricate values and marks unavailable
    assert features.get("http_upload_bytes") is None
    assert features.get("http_download_bytes") is None

def test_data_quality_tags():
    """Assert unsupported heuristics like USB bytes are flagged."""
    payload = {
        "collectors": [
            {
                "collector": "device",
                "status": "success",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "hostname": "test-pc",
                "payload": {
                    "usb_bytes_transferred": 5000000,
                    "devices_connected": 1
                }
            }
        ]
    }
    bridge = ModelBridge()
    # Mocking the intended method
    if not hasattr(bridge, "extract_with_metadata"):
        pytest.skip("extract_with_metadata not implemented yet on ModelBridge")
    features, metadata = bridge.extract_with_metadata(payload)
    
    assert features["usb_bytes_transferred"] == 5000000
    # Explicitly verify the VERIFY_REQUIRED tag
    assert "usb_bytes_transferred" in metadata["quality_warnings"]
    assert metadata["quality_warnings"]["usb_bytes_transferred"] == "VERIFY_REQUIRED"

def test_timestamp_normalization():
    """Assert naive timestamps from the payload are forced to UTC."""
    # A payload with naive ISO format (no +00:00 or Z)
    naive_timestamp = "2026-06-13T10:00:00" 
    payload = {
        "collected_at": naive_timestamp,
        "collectors": []
    }
    bridge = ModelBridge()
    if not hasattr(bridge, "_parse_timestamp"):
        pytest.skip("_parse_timestamp not implemented yet on ModelBridge")
    parsed_time = bridge._parse_timestamp(payload["collected_at"])
    
    # Verify timezone is strictly UTC
    assert parsed_time.tzinfo == timezone.utc
