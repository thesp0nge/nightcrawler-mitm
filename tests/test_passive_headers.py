# tests/test_passive_headers.py
import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.headers import check_security_headers
except ImportError:
    pytest.fail("Could not import check_security_headers", pytrace=False)


# Helper function to find calls
def find_log_call(mock_logger, finding_type_substr):
    for call in mock_logger.call_args_list:
        if finding_type_substr in call.kwargs.get("finding_type", ""):
            return call
    return None


# Fixtures are loaded from conftest.py


def test_missing_all_headers(mock_addon, sample_url):
    """Test: No security headers are present."""
    headers = http.Headers()
    check_security_headers(headers, sample_url, mock_addon)
    call = find_log_call(mock_addon._log_finding, "Missing Header(s)")
    assert call is not None, "Log for 'Missing Header(s)' was not found"
    assert call.kwargs["level"] == "WARN"


def test_info_disclosure_server_version(mock_addon, sample_url):
    """Test: Server header discloses specific version."""
    headers = http.Headers(Server="Apache/2.4.58 (Ubuntu)")
    check_security_headers(headers, sample_url, mock_addon)

    call = find_log_call(mock_addon._log_finding, "Info Disclosure (Server)")
    assert call is not None, "Log for 'Info Disclosure (Server)' was not found"
    assert call.kwargs["level"] == "WARN"

    # --- FINAL CORRECTED ASSERTION ---
    expected_detail = "Potentially specific version disclosed in 'Server' header: Apache/2.4.58 (Ubuntu)"
    assert call.kwargs["detail"] == expected_detail
