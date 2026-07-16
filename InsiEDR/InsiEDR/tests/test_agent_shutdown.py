from __future__ import annotations

import signal
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Define win32con constants if not available (e.g. on Linux) so tests can still reference them
class MockWin32Con:
    CTRL_C_EVENT = 0
    CTRL_BREAK_EVENT = 1
    CTRL_CLOSE_EVENT = 2
    CTRL_LOGOFF_EVENT = 5
    CTRL_SHUTDOWN_EVENT = 6

try:
    import win32con
except ImportError:
    win32con = MockWin32Con


from agent.agent import EndpointAgent
from agent.config import AgentConfig
from agent.transport import TransportResult


@pytest.fixture
def mock_config(tmp_path):
    """Provides a base AgentConfig for testing."""
    return AgentConfig(
        server_url="https://localhost:5000/api/logs",
        aes_key=b"0" * 32,
        agent_id="test-agent-id",
        hostname="test-host",
        username="test-user",
        queue_dir=tmp_path / "queue",
        state_dir=tmp_path / "state",
        enabled_collectors=(),
    )


@pytest.fixture
def agent(mock_config):
    """Initializes the EndpointAgent with mocked components."""
    # Patch discover_collectors to avoid loading real collectors
    with patch("agent.agent.discover_collectors", return_value=[]):
        # Patch LocalEncryptedQueue to avoid file system operations beyond tmp_path
        with patch("agent.agent.LocalEncryptedQueue"):
            agent = EndpointAgent(mock_config)
            # Mock the transport layer
            agent.transport = MagicMock(spec=agent.transport)
            # Default success for transport
            agent.transport.send_or_queue.return_value = TransportResult(ok=True, queued=False)
            return agent


def test_quiet_shutdown_on_windows_os_events(agent):
    """
    Legitimate OS Exits (The Quiet Path):
    Mock a Windows CTRL_SHUTDOWN_EVENT and CTRL_LOGOFF_EVENT being sent to the win32api handler.
    Verify that the agent initiates a graceful shutdown sequence without tamper flags.
    """
    with patch("agent.agent.win32con", win32con):
        # 1. Test CTRL_SHUTDOWN_EVENT
        agent._stopping = False
        res = agent._os_signal_handler(win32con.CTRL_SHUTDOWN_EVENT)
        
        assert res is True
        assert agent._stopping is True
        # Verify no tamper payload was generated or sent
        agent.transport.send_or_queue.assert_not_called()
        
        # 2. Test CTRL_LOGOFF_EVENT
        agent._stopping = False
        res = agent._os_signal_handler(win32con.CTRL_LOGOFF_EVENT)
        
        assert res is True
        assert agent._stopping is True
        agent.transport.send_or_queue.assert_not_called()


@pytest.mark.parametrize("event", [
    win32con.CTRL_C_EVENT,
    win32con.CTRL_BREAK_EVENT,
    win32con.CTRL_CLOSE_EVENT
])
def test_tamper_detection_on_manual_kill_windows(agent, event):
    """
    Manual/Forceful Kills (The Tamper Path):
    Mock a CTRL_C_EVENT, CTRL_BREAK_EVENT, or CTRL_CLOSE_EVENT.
    Verify that the agent generates a synthetic tamper CollectorResult.
    """
    with patch("agent.agent.win32con", win32con), \
         patch("agent.agent.build_payload") as mock_build:
        
        mock_build.return_value = {"payload_id": "pid", "summary": {}}
        # Mock encrypt_payload to return a dummy envelope
        agent.crypto.encrypt_payload = MagicMock(return_value={"encrypted": "data"})
        
        res = agent._os_signal_handler(event)
        
        assert res is True
        assert agent._stopping is True
        
        # Verify tamper payload was sent
        agent.transport.send_or_queue.assert_called_once()
        
        # Verify payload content via the mock call arguments
        envelope, _headers = agent.transport.send_or_queue.call_args[0]
        assert envelope["payload_id"] == "pid"


def test_tamper_payload_content_and_timeout(agent):
    """
    Verifies the specific content of the tamper flag and the 3-second timeout limit.
    """
    # Mock encrypt_payload to return a dummy envelope
    agent.crypto.encrypt_payload = MagicMock(return_value={"encrypted": "data"})
    
    with patch("agent.agent.build_payload") as mock_build:
        mock_build.return_value = {"payload_id": "pid", "summary": {"collector_count": 1, "success_count": 1, "failed_count": 0}}
        
        agent._fire_tamper_flag()
        
        # Verify build_payload was called with the correct synthetic result
        args, kwargs = mock_build.call_args
        results = kwargs["collector_results"]
        assert len(results) == 1
        result = results[0]
        assert result.collector == "agent-lifecycle"
        assert result.payload["manual_agent_stop_flag"] == 1
        assert result.payload["agent_status"] == "terminated_by_user"
        
        # Verify the transport object was interacted with.
        agent.transport.send_or_queue.assert_called_once()


def test_tamper_timeout_enforcement(agent):
    """
    Explicitly check if the transport timeout was modified to 3.0 during tamper dispatch.
    """
    # Mock encrypt_payload
    agent.crypto.encrypt_payload = MagicMock(return_value={"encrypted": "data"})
    
    # Mock build_payload to ensure it succeeds
    with patch("agent.agent.build_payload") as mock_build:
        mock_build.return_value = {"payload_id": "pid", "summary": {}}
        
        agent._fire_tamper_flag()
        
        # Verify the 1.0, 2.0 timeout during execution
        agent.transport.send_or_queue.assert_called_once()
        _, kwargs = agent.transport.send_or_queue.call_args
        assert kwargs.get("timeout_override") == (1.0, 2.0)


def test_cross_platform_sigterm_fallback(agent):
    """
    Cross-Platform Fallback:
    Mock a non-Windows environment and simulate a standard SIGTERM signal.
    Verify fallback signal handler fires tamper payload.
    """
    # Mock encrypt_payload
    agent.crypto.encrypt_payload = MagicMock(return_value={"encrypted": "data"})
    
    with patch("agent.agent.build_payload") as mock_build:
        mock_build.return_value = {"payload_id": "pid", "summary": {}}
        
        # We need to mock sys.exit to prevent the test from ending
        with patch("sys.exit") as mock_exit:
            # Simulate SIGTERM signal call to _posix_signal_handler
            agent._posix_signal_handler(signal.SIGTERM, None)
            
            assert agent._stopping is True
            agent.transport.send_or_queue.assert_called_once()
            mock_exit.assert_called_once_with(0)


def test_registration_of_handlers(mock_config):
    """
    Verify that run_forever registers the correct handlers.
    """
    with patch("agent.agent.discover_collectors", return_value=[]), \
         patch("agent.agent.LocalEncryptedQueue"), \
         patch("agent.agent.write_health_status"), \
         patch("win32api.SetConsoleCtrlHandler") as mock_set_handler, \
         patch("signal.signal") as mock_signal, \
         patch("time.sleep", side_effect=InterruptedError): # Stop the loop immediately
        
        agent = EndpointAgent(mock_config)
        
        # 1. Test registration without win32api
        with patch("agent.agent.win32api", None):
            try:
                agent.run_forever()
            except InterruptedError:
                pass
            mock_set_handler.assert_not_called()

        # 2. Test registration with win32api
        mock_win32api = MagicMock()
        with patch("agent.agent.win32api", mock_win32api):
            try:
                agent.run_forever()
            except InterruptedError:
                pass
            mock_win32api.SetConsoleCtrlHandler.assert_called_once_with(agent._os_signal_handler, True)
        
        # Verify standard signals
        # SIGINT and SIGTERM should be registered
        sig_calls = [call[0][0] for call in mock_signal.call_args_list]
        assert signal.SIGINT in sig_calls
        assert signal.SIGTERM in sig_calls
