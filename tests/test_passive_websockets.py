# tests/test_passive_websockets.py
# Unit tests for the WebSocket passive authentication scanner.

import pytest
from mitmproxy.test import tflow
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.websockets import check_websocket_authentication
except ImportError:
    pytest.fail("Could not import check_websocket_authentication", pytrace=False)

# Fixtures mock_addon and sample_url are loaded from conftest.py


def test_websocket_with_no_cookie_header(mock_addon):
    """Test: A WebSocket upgrade with no Cookie header should trigger a WARN."""
    # Create a mock flow with a request that has no Cookie header
    flow = tflow.tflow()  # A simple test flow
    flow.request.url = "wss://example.com/socket"

    mock_logger = MagicMock()
    check_websocket_authentication(flow, mock_addon, mock_logger)

    # Assert that a finding was logged
    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["level"] == "WARN"
    assert kwargs["finding_type"] == "Passive Scan - WebSocket Without Cookie"


def test_websocket_with_irrelevant_cookies(mock_addon):
    """Test: A WebSocket upgrade with non-session cookies should trigger a WARN."""
    flow = tflow.tflow()
    flow.request.url = "wss://example.com/socket"
    flow.request.headers["Cookie"] = "tracking_id=12345; theme=dark"

    mock_logger = MagicMock()
    check_websocket_authentication(flow, mock_addon, mock_logger)

    # Assert that a finding was logged
    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["level"] == "WARN"
    assert kwargs["finding_type"] == "Passive Scan - WebSocket No Session Cookie"
    assert "tracking_id=12345" in kwargs["evidence"]["cookie_header"]


def test_websocket_with_session_cookie(mock_addon):
    """Test: A WebSocket upgrade with a common session cookie should NOT trigger a finding."""
    flow = tflow.tflow()
    flow.request.url = "wss://example.com/socket"
    # Use a common session cookie name
    flow.request.headers["Cookie"] = (
        "some_other=value; sessionid=abcdef12345; theme=dark"
    )

    mock_logger = MagicMock()
    check_websocket_authentication(flow, mock_addon, mock_logger)

    # Assert that NO finding was logged
    mock_addon._log_finding.assert_not_called()


def test_websocket_with_jessionid_cookie(mock_addon):
    """Test: Another common session cookie name should also be accepted."""
    flow = tflow.tflow()
    flow.request.url = "wss://example.com/socket"
    flow.request.headers["Cookie"] = "JSESSIONID=SDFG9876SDFG987"

    mock_logger = MagicMock()
    check_websocket_authentication(flow, mock_addon, mock_logger)

    # Assert that NO finding was logged
    mock_addon._log_finding.assert_not_called()
