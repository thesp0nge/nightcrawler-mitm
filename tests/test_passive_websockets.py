# tests/test_passive_websockets.py
# Unit tests for the WebSocket passive authentication scanner.

import pytest
from mitmproxy.test import tflow
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.websockets import WebSocketScanner
except ImportError:
    pytest.fail("Could not import WebSocketScanner", pytrace=False)

@pytest.mark.asyncio
async def test_websocket_with_no_cookie_header(mock_addon):
    """Test: A WebSocket upgrade with no Cookie header should trigger a WARN."""
    flow = tflow.tflow()
    flow.request.url = "wss://example.com/socket"
    flow.request.headers["Upgrade"] = "websocket"

    scanner = WebSocketScanner(mock_addon, MagicMock())
    await scanner.scan_request(flow.request)

    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["finding_type"] == "Passive Scan - WebSocket Without Cookie"

@pytest.mark.asyncio
async def test_websocket_with_session_cookie(mock_addon):
    """Test: A WebSocket upgrade with a common session cookie should NOT trigger a finding."""
    flow = tflow.tflow()
    flow.request.url = "wss://example.com/socket"
    flow.request.headers["Upgrade"] = "websocket"
    flow.request.headers["Cookie"] = "sessionid=abcdef12345"

    scanner = WebSocketScanner(mock_addon, MagicMock())
    await scanner.scan_request(flow.request)

    mock_addon._log_finding.assert_not_called()
