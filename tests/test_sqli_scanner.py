# tests/test_sqli_scanner.py
import pytest
import httpx
import respx
import time
from unittest.mock import MagicMock
from nightcrawler.sqli_scanner import scan_sqli_basic, scan_sqli_boolean_based

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL = "http://test.com/products"
TARGET_PARAM = "id"
SQLI_PAYLOADS = ["'", "''", "AND SLEEP(5)"]

# Fixtures mock_addon and target_info_get are loaded from conftest.py

@pytest.mark.asyncio
@respx.mock
async def test_sqli_error_based(mock_addon, target_info_get):
    """Test: Detects SQLi based on database error patterns in the response."""
    payload = "'"
    # Mock a response containing a classic SQL error message
    respx.get(TARGET_URL, params={TARGET_PARAM: "test" + payload}).respond(
        200, text="<html>Error: You have an error in your SQL syntax; check the manual...</html>"
    )

    await scan_sqli_basic(
        target_info_get,
        {},
        httpx.AsyncClient(),
        [payload],
        mock_addon,
        MagicMock(),
        mode="append"
    )

    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    assert args[1] == "SQLi Found? (Error-Based)"
    assert kwargs["confidence"] == "HIGH"


@pytest.mark.asyncio
@respx.mock
async def test_sqli_time_based_verified(mocker, mock_addon, target_info_get):
    """Test: Detects and verifies time-based SQLi by checking proportional delays."""
    payload = "AND SLEEP(5)"
    
    # Mock time.time() to simulate 5s delay then 2s delay
    # sequence: 
    # 1. start_time (0)
    # 2. end_time (5.1) -> duration > 4.5
    # 3. v_start (10)
    # 4. v_end (12.1) -> v_duration ~ 2.1
    class TimeGenerator:
        def __init__(self):
            self.times = [0.0, 5.1, 10.0, 12.1]
            self.idx = 0
        def __call__(self):
            val = self.times[self.idx]
            self.idx = (self.idx + 1) % len(self.times)
            return val

    mocker.patch("nightcrawler.sqli_scanner.time.time", TimeGenerator())
    
    # Mock requests
    respx.get(TARGET_URL).respond(200)

    await scan_sqli_basic(
        target_info_get,
        {},
        httpx.AsyncClient(),
        [payload],
        mock_addon,
        MagicMock(),
        mode="append"
    )

    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    assert "Time-Based" in args[1]
    assert kwargs["confidence"] == "HIGH"
    assert "Verified" in args[3]


@pytest.mark.asyncio
@respx.mock
async def test_sqli_boolean_based_with_stability(mock_addon, target_info_get):
    """Test: Detects boolean-based SQLi and confirms it with a stability check."""
    # Boolean payloads from scanner: (" AND 1=1", " AND 1=0")
    true_payload = " AND 1=1"
    false_payload = " AND 1=0"
    
    # 1. True request (Length 100)
    respx.get(TARGET_URL, params={TARGET_PARAM: "test" + true_payload}).respond(200, text="A" * 100)
    # 2. False request (Length 50)
    respx.get(TARGET_URL, params={TARGET_PARAM: "test" + false_payload}).respond(200, text="A" * 50)
    # 3. Stability checks (Original requests must have same length)
    respx.get(TARGET_URL, params={TARGET_PARAM: "test"}).respond(200, text="A" * 80)

    await scan_sqli_boolean_based(
        target_info_get,
        {},
        httpx.AsyncClient(),
        mock_addon,
        MagicMock()
    )

    # If stability check (two calls to original) returns same length, it logs
    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    assert "Boolean-Based" in args[1]
    assert kwargs["confidence"] == "MEDIUM"


@pytest.mark.asyncio
@respx.mock
async def test_sqli_boolean_unstable_ignored(mock_addon, target_info_get):
    """Test: Boolean-based SQLi is ignored if the page content length is unstable."""
    true_payload = " AND 1=1"
    false_payload = " AND 1=0"
    
    respx.get(TARGET_URL, params={TARGET_PARAM: "test" + true_payload}).respond(200, text="A" * 100)
    respx.get(TARGET_URL, params={TARGET_PARAM: "test" + false_payload}).respond(200, text="A" * 50)
    
    # Stability check returns DIFFERENT lengths
    route = respx.get(TARGET_URL, params={TARGET_PARAM: "test"})
    route.side_effect = [
        httpx.Response(200, text="Length 1"),
        httpx.Response(200, text="Length 2 is different")
    ]

    await scan_sqli_boolean_based(
        target_info_get,
        {},
        httpx.AsyncClient(),
        mock_addon,
        MagicMock()
    )

    mock_addon._log_finding.assert_not_called()
