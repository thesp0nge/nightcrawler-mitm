# tests/test_sqli_scanner.py
import pytest
import httpx
import respx
import time
import re
from unittest.mock import MagicMock
try:
    from nightcrawler.active_scans.sqli_scanner import SQLiScanner
except ImportError:
    pytest.fail("Could not import SQLiScanner", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL = "http://test.com/products"
TARGET_PARAM = "id"

@pytest.mark.asyncio
@respx.mock
async def test_sqli_error_based(mock_addon, target_info_get):
    """Test: Detects SQLi based on database error patterns."""
    payload = "'"
    mock_addon.sqli_payloads = [payload]
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: "1"}
    
    respx.route(url=re.compile(r".*")).respond(
        200, text="<html>Error: You have an error in your SQL syntax; check the manual...</html>"
    )

    scanner = SQLiScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # SQLiScanner uses keyword arguments
    assert kwargs["level"] in ["ERROR", "WARN"]
    assert "SQLi Found" in kwargs["finding_type"]

@pytest.mark.asyncio
@respx.mock
async def test_sqli_boolean_based_hit(mock_addon, target_info_get):
    """Test: Detects boolean-based blind SQLi."""
    mock_addon.sqli_payloads = [] # Disable basic scan
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: "1"}
    
    def sqli_side_effect(request):
        url_str = str(request.url).lower()
        if "and+1%3d1" in url_str:
            return httpx.Response(200, text="A" * 100)
        elif "and+1%3d0" in url_str:
            return httpx.Response(200, text="A" * 50)
        else:
            return httpx.Response(200, text="A" * 100) # Stable baseline

    respx.route(url=re.compile(r".*")).side_effect = sqli_side_effect

    scanner = SQLiScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # SQLiScanner uses keyword arguments
    assert "Boolean-Based" in kwargs["finding_type"]
