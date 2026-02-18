# tests/test_active_command_injection.py
import pytest
import respx
import httpx
import time
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.command_injection import scan_command_injection
except ImportError:
    pytest.fail("Could not import scan_command_injection")

pytestmark = pytest.mark.asyncio

# Fixtures are loaded from conftest.py


@pytest.mark.asyncio
async def test_cmd_injection_time_based(mocker, mock_addon, target_info_get):
    """Test: Detects time-based command injection by using a robust time mock."""
    payload = "| sleep 5 #"

    class TimeGenerator:
        def __init__(self):
            self.times_to_return = [0.0, 5.0]
            self.call_index = 0

        def __call__(self):
            ret_val = self.times_to_return[self.call_index]
            self.call_index += 1
            return ret_val

    mocker.patch(
        "nightcrawler.active_scans.command_injection.time.time", TimeGenerator()
    )

    # Mock the http_client's request method
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_response = httpx.Response(200)
    mock_client.request.return_value = mock_response

    await scan_command_injection(
        target_info_get, {}, mock_client, [payload], mock_addon, MagicMock()
    )

    # Now the duration check (5.0 - 0.0 > 4.5) should pass, and the finding should be logged.
    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["level"] == "ERROR"
    assert "Time-Based" in kwargs["finding_type"]
    assert "Duration: 5.00s" in kwargs["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_cmd_injection_output_based(mock_addon, target_info_get):
    """Test: Detects output-based command injection."""
    payload = "| whoami"
    # Mock the response to contain the expected output of the 'whoami' command
    respx.get("http://test.com/search", params={"query": "test" + payload}).respond(
        200, text="some output... root ...more output"
    )

    await scan_command_injection(
        target_info_get, {}, httpx.AsyncClient(), [payload], mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["level"] == "ERROR"
    assert "Output-Based" in kwargs["finding_type"]
