# tests/test_passive_headers.py
# Unit tests for the passive header scanning logic.

import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.headers import HeaderScanner
except ImportError:
    pytest.fail("Could not import HeaderScanner", pytrace=False)

def find_log_call(mock_logger, finding_type_substr):
    for call in mock_logger.call_args_list:
        if finding_type_substr in call.kwargs.get("finding_type", ""):
            return call
    return None

# Fixtures are loaded from conftest.py

@pytest.mark.asyncio
async def test_missing_all_headers(mock_addon, sample_url):
    """Test: No security headers are present."""
    headers = http.Headers()
    scanner = HeaderScanner(mock_addon, MagicMock())
    await scanner.scan_response(http.Response.make(200, b"", headers), sample_url)

    call = find_log_call(mock_addon._log_finding, "Missing Header(s)")
    assert call is not None
    assert call.kwargs["level"] == "WARN"

@pytest.mark.asyncio
async def test_info_disclosure_server_version(mock_addon, sample_url):
    """Test: Server header discloses specific version."""
    headers = http.Headers(Server="Apache/2.4.58 (Ubuntu)")
    scanner = HeaderScanner(mock_addon, MagicMock())
    await scanner.scan_response(http.Response.make(200, b"", headers), sample_url)

    call = find_log_call(mock_addon._log_finding, "Info Disclosure (Server)")
    assert call is not None
    assert call.kwargs["level"] == "WARN"

@pytest.mark.asyncio
async def test_csp_weak_directives(mock_addon, sample_url):
    """Test: CSP has multiple weak directives."""
    headers = http.Headers(
        Content_Security_Policy="script-src 'unsafe-inline' *; object-src 'none'"
    )
    response = http.Response.make(200, b"", headers)
    scanner = HeaderScanner(mock_addon, MagicMock())
    await scanner.scan_response(response, sample_url)

    call = find_log_call(mock_addon._log_finding, "Weak CSP")
    assert call is not None
    assert "'unsafe-inline'" in call.kwargs["detail"]
