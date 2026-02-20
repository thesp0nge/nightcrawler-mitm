# tests/test_active_command_injection.py
import pytest
import respx
import httpx
import time
import re
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.command_injection import CommandInjectionScanner
except ImportError:
    pytest.fail("Could not import CommandInjectionScanner")

pytestmark = pytest.mark.asyncio

# Fixtures are loaded from conftest.py

@pytest.mark.asyncio
async def test_cmd_injection_time_based(mocker, mock_addon, target_info_get):
    """Test: Detects time-based command injection by using a robust time mock."""
    payload = "| sleep 5 #"
    mock_addon.cmd_injection_payloads = [payload]

    class TimeGenerator:
        def __init__(self):
            # sequence:
            # 1. start_time (0.0)
            # 2. end_time (5.1) -> duration > 4.5
            # 3. v_start (10.0)
            # 4. v_end (12.1) -> v_duration ~ 2.1
            self.times_to_return = [0.0, 5.1, 10.0, 12.1]
            self.call_index = 0

        def __call__(self):
            ret_val = self.times_to_return[self.call_index]
            self.call_index = (self.call_index + 1) % len(self.times_to_return)
            return ret_val

    mocker.patch(
        "nightcrawler.active_scans.command_injection.time.time", TimeGenerator()
    )

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_response = httpx.Response(200)
    mock_client.request.side_effect = [mock_response, mock_response, mock_response, mock_response]

    scanner = CommandInjectionScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, mock_client)

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # CommandInjectionScanner uses keyword arguments
    assert kwargs["level"] == "ERROR"
    assert "Time-Based" in kwargs["finding_type"]

@pytest.mark.asyncio
@respx.mock
async def test_cmd_injection_output_based(mock_addon, target_info_get):
    """Test: Detects output-based command injection."""
    payload = " && id"
    mock_addon.cmd_injection_payloads = [payload]
    respx.get(url=re.compile(r".*")).respond(
        200, text="uid=0(root) gid=0(root) groups=0(root)"
    )

    scanner = CommandInjectionScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # CommandInjectionScanner uses keyword arguments
    assert kwargs["level"] == "ERROR"
    assert "Legacy Output" in kwargs["finding_type"]
