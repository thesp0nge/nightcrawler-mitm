# tests/test_passive_headers.py
# Unit tests for the passive header scanning logic.

import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.headers import check_security_headers
except ImportError:
    pytest.fail("Could not import check_security_headers", pytrace=False)


# Helper function to find a specific call in the mock's call list
def find_log_call(mock_logger, finding_type_substr):
    for call in mock_logger.call_args_list:
        if finding_type_substr in call.kwargs.get("finding_type", ""):
            return call
    return None


# Fixtures are loaded from conftest.py


def test_missing_all_headers(mock_addon, sample_url):
    """Test: No security headers are present."""
    headers = http.Headers()
    # Pass a mock logger as the final argument
    check_security_headers(
        http.Response.make(200, b"", headers), sample_url, mock_addon, MagicMock()
    )

    call = find_log_call(mock_addon._log_finding, "Missing Header(s)")
    assert call is not None, "Log for 'Missing Header(s)' was not found"
    assert call.kwargs["level"] == "WARN"
    assert "Strict-Transport-Security" in call.kwargs["detail"]


def test_info_disclosure_server_version(mock_addon, sample_url):
    """Test: Server header discloses specific version."""
    headers = http.Headers(Server="Apache/2.4.58 (Ubuntu)")
    # Pass a mock logger as the final argument
    check_security_headers(
        http.Response.make(200, b"", headers), sample_url, mock_addon, MagicMock()
    )

    call = find_log_call(mock_addon._log_finding, "Info Disclosure (Server)")
    assert call is not None, "Log for 'Info Disclosure (Server)' was not found"
    assert call.kwargs["level"] == "WARN"
    expected_detail = "Potentially specific version disclosed in 'Server' header: Apache/2.4.58 (Ubuntu)"
    assert call.kwargs["detail"] == expected_detail


def test_csp_weak_directives(mock_addon, sample_url):
    """Test: CSP has multiple weak directives."""
    headers = http.Headers(
        Content_Security_Policy="script-src 'unsafe-inline' *; object-src 'none'"
    )
    response = http.Response.make(200, b"", headers)
    # Pass a mock logger as the final argument
    check_security_headers(response, sample_url, mock_addon, MagicMock())

    call = find_log_call(mock_addon._log_finding, "Weak CSP")
    assert call is not None
    assert call.kwargs["level"] == "WARN"
    assert "'unsafe-inline'" in call.kwargs["detail"]
    assert "Wildcard (*) source" in call.kwargs["detail"]
