# tests/test_passive_headers.py
# Unit tests for the passive header scanning logic.

import pytest
import re
from mitmproxy import http  # Needed to create Headers object
from unittest.mock import MagicMock  # For mocking addon instance

# Import the function(s) to test
try:
    # Adjust import based on your structure
    from nightcrawler.passive_scans.headers import check_security_headers
except ImportError:
    pytest.fail("Could not import check_security_headers", pytrace=False)

# --- Fixtures ---


@pytest.fixture
def mock_addon(mocker):
    """Pytest fixture to create a mock MainAddon instance with a mock logger."""
    instance = mocker.MagicMock(name="MainAddonInstance")
    instance._log_finding = mocker.MagicMock(name="_log_finding")
    mocker.resetall()  # Ensure clean mock for each test
    return instance


@pytest.fixture
def sample_url():
    """A sample HTTPS URL for testing."""
    return "https://example.com/test"


# --- Test Cases ---


def test_missing_all_headers(mock_addon, sample_url):
    """
    Test: No security headers are present.
    Expect exactly one WARN log for missing headers with correct details.
    """
    headers = http.Headers()  # Empty headers object
    # Call the function under test, passing the mock addon instance
    check_security_headers(headers, sample_url, mock_addon)

    # --- Refined Assertions ---
    # 1. Filter all calls made to the mock logger to find those for missing headers
    missing_header_calls = [
        call
        for call in mock_addon._log_finding.call_args_list
        if call.kwargs.get("finding_type") == "Passive Scan - Missing Header(s)"
    ]

    # 2. Assert that exactly one such call was made
    assert (
        len(missing_header_calls) == 1
    ), f"Expected 1 'Missing Header(s)' log, but found {len(missing_header_calls)}. All Calls: {mock_addon._log_finding.call_args_list}"

    # 3. Get the arguments of that specific call
    # call object structure: call.args (tuple of positional), call.kwargs (dict of keyword)
    call_kwargs = missing_header_calls[0].kwargs

    # 4. Assert the arguments of that specific call are correct
    assert call_kwargs.get("level") == "WARN"
    assert call_kwargs.get("url") == sample_url
    # Check that the detail string mentions specific expected missing headers
    detail_str = call_kwargs.get("detail", "")
    assert isinstance(detail_str, str)
    assert "Strict-Transport-Security" in detail_str
    assert "Content-Security-Policy" in detail_str
    assert "X-Frame-Options" in detail_str
    # Check that evidence contains the 'missing' key with a list value
    evidence_dict = call_kwargs.get("evidence")
    assert isinstance(evidence_dict, dict)
    assert "missing" in evidence_dict
    assert isinstance(evidence_dict["missing"], list)
    # Optionally check specific headers in the evidence list (might be brittle if list changes)
    assert "Strict-Transport-Security" in evidence_dict["missing"]
    assert "Permissions-Policy" in evidence_dict["missing"]
    # --- End Refined Assertions ---


def test_hsts_present_weak_maxage(mock_addon, sample_url):
    """Test: HSTS header present but with short max-age."""
    headers = http.Headers(
        Strict_Transport_Security="max-age=1000"  # Very short max-age
    )
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Weak HSTS",
        url=sample_url,
        detail="HSTS max-age (1000) is less than recommended minimum (15552000).",
        evidence={"header": "Strict-Transport-Security: max-age=1000"},
    )


def test_hsts_present_no_maxage(mock_addon, sample_url):
    """Test: HSTS header present but missing max-age directive."""
    headers = http.Headers(Strict_Transport_Security="includeSubDomains")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Weak HSTS",
        url=sample_url,
        detail="HSTS header present but 'max-age' directive is missing.",
        evidence={"header": "Strict-Transport-Security: includeSubDomains"},
    )


def test_xcto_incorrect_value(mock_addon, sample_url):
    """Test: X-Content-Type-Options has wrong value."""
    headers = http.Headers(X_Content_Type_Options="ALLOW")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Incorrect X-Content-Type-Options",
        url=sample_url,
        detail="X-Content-Type-Options set to 'ALLOW' instead of recommended 'nosniff'.",
        evidence={"header": "X-Content-Type-Options: ALLOW"},
    )


def test_xcto_correct_value(mock_addon, sample_url):
    """Test: X-Content-Type-Options is correct ('nosniff')."""
    headers = http.Headers(X_Content_Type_Options="nosniff")
    check_security_headers(headers, sample_url, mock_addon)
    # Assert that the specific warning for incorrect XCTO was NOT called
    for call in mock_addon._log_finding.call_args_list:
        assert (
            call.kwargs["finding_type"]
            != "Passive Scan - Incorrect X-Content-Type-Options"
        )


def test_info_disclosure_server_version(mock_addon, sample_url):
    """Test: Server header discloses specific version."""
    headers = http.Headers(Server="Apache/2.4.58 (Ubuntu)")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",  # Should be WARN due to version disclosure
        finding_type="Passive Scan - Info Disclosure (Server)",
        url=sample_url,
        detail="Potentially specific version disclosed in 'Server' header: Apache/2.4.58 (Ubuntu)",
        evidence={"header": "Server: Apache/2.4.58 (Ubuntu)"},
    )


def test_info_disclosure_powered_by(mock_addon, sample_url):
    """Test: X-Powered-By header is present."""
    headers = http.Headers(X_Powered_By="PHP/8.1.2")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",  # Should be WARN as it's unnecessary info
        finding_type="Passive Scan - Info Disclosure (X-Powered-By)",
        url=sample_url,
        detail="Potentially unnecessary info disclosed in 'X-Powered-By': PHP/8.1.2",
        evidence={"header": "X-Powered-By: PHP/8.1.2"},
    )


def test_info_disclosure_via(mock_addon, sample_url):
    """Test: Via header is present indicating a proxy."""
    headers = http.Headers(Via="1.1 vegur")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="INFO",  # INFO level is appropriate for Via
        finding_type="Passive Scan - Info Disclosure (Via)",
        url=sample_url,
        detail="Proxy detected via 'Via' header: 1.1 vegur",
        evidence={"header": "Via: 1.1 vegur"},
    )


def test_caching_public_sensitive(mock_addon, sample_url):
    """Test: Cache-Control: public on application/json content."""
    headers = http.Headers(
        Cache_Control="public, max-age=3600",
        Content_Type="application/json; charset=utf-8",
    )
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Potential Sensitive Data Caching",
        url=sample_url,
        detail="'Cache-Control: public' found on potentially sensitive content type 'application/json; charset=utf-8'.",
        evidence={"header": "Cache-Control: public, max-age=3600"},
    )


def test_caching_not_disabled_sensitive(mock_addon, sample_url):
    """Test: Caching not explicitly disabled on sensitive type (INFO level)."""
    headers = http.Headers(
        Content_Type="application/json"
    )  # No Cache-Control or Pragma: no-cache
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="INFO",
        finding_type="Passive Scan - Caching Not Disabled?",
        url=sample_url,
        detail="Caching not explicitly disabled (no-cache/no-store) on potentially sensitive content type 'application/json'. Verify cache headers.",
        evidence={"Cache-Control": None, "Pragma": None},
    )


def test_cors_wildcard(mock_addon, sample_url):
    """Test: ACAO is wildcard (*)."""
    headers = http.Headers(Access_Control_Allow_Origin="*")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",  # Often WARN, could be ERROR depending on policy
        finding_type="Passive Scan - Permissive CORS (Wildcard)",
        url=sample_url,
        detail="Access-Control-Allow-Origin is wildcard (*), allowing any origin.",
        evidence={"header": "Access-Control-Allow-Origin: *"},
    )


def test_cors_null(mock_addon, sample_url):
    """Test: ACAO is null."""
    headers = http.Headers(Access_Control_Allow_Origin="null")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Permissive CORS (Null)",
        url=sample_url,
        detail="Access-Control-Allow-Origin is 'null'. This can be insecure in some contexts.",
        evidence={"header": "Access-Control-Allow-Origin: null"},
    )


def test_secure_headers_present(mock_addon, sample_url):
    """Test: All recommended security headers are present and look OK."""
    headers = http.Headers(
        Strict_Transport_Security="max-age=31536000; includeSubDomains",
        Content_Security_Policy="default-src 'self'; script-src 'self' https://trusted.cdn; object-src 'none'; base-uri 'self';",
        X_Content_Type_Options="nosniff",
        X_Frame_Options="SAMEORIGIN",
        Referrer_Policy="strict-origin-when-cross-origin",
        Permissions_Policy="geolocation=(), microphone=()",
        Cross_Origin_Opener_Policy="same-origin",
        Cross_Origin_Embedder_Policy="require-corp",
        Cross_Origin_Resource_Policy="same-origin",
    )
    check_security_headers(headers, sample_url, mock_addon)
    # Check that specific WARN/ERROR findings were NOT logged
    for call in mock_addon._log_finding.call_args_list:
        assert call.kwargs["finding_type"] != "Passive Scan - Missing Header(s)"
        assert call.kwargs["finding_type"] != "Passive Scan - Weak HSTS"
        assert (
            call.kwargs["finding_type"]
            != "Passive Scan - Incorrect X-Content-Type-Options"
        )
        # Could add more specific negative assertions if needed


def test_csp_unsafe_inline_script(mock_addon, sample_url):
    """Test: CSP allows unsafe-inline for scripts."""
    headers = http.Headers(
        Content_Security_Policy="default-src 'self'; script-src 'self' 'unsafe-inline'"
    )
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Weak CSP ('unsafe-inline')",
        url=sample_url,
        detail="Potential weak directives/sources found in CSP: 'unsafe-inline'",  # Check basic detail
        evidence=pytest.approx(dict),
    )


def test_csp_wildcard_source(mock_addon, sample_url):
    """Test: CSP allows wildcard * for default-src."""
    headers = http.Headers(Content_Security_Policy="default-src *; object-src 'none'")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Weak CSP (Wildcard Source)",
        url=sample_url,
        detail="Potential weak directives/sources found in CSP: Wildcard (*) source in script-src/default-src",
        evidence=pytest.approx(dict),
    )


def test_csp_missing_base_uri(mock_addon, sample_url):
    """Test: CSP is present but missing base-uri directive."""
    headers = http.Headers(Content_Security_Policy="default-src 'self'")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Weak CSP (Missing base-uri)",
        url=sample_url,
        detail="Potential weak directives/sources found in CSP: Missing base-uri",
        evidence=pytest.approx(dict),
    )


def test_info_disclosure_server_detailed(mock_addon, sample_url):
    """Test: Server header discloses specific version."""
    headers = http.Headers(Server="SomeWebServer/1.2.3 (Debian)")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Server)",
        url=sample_url,
        detail="Potentially verbose/identifying info disclosed in 'Server' header: SomeWebServer/1.2.3 (Debian)",
        evidence={"header": "Server: SomeWebServer/1.2.3 (Debian)"},
    )


def test_info_disclosure_server_generic(mock_addon, sample_url):
    """Test: Server header is generic, should be INFO."""
    headers = http.Headers(Server="nginx")
    check_security_headers(headers, sample_url, mock_addon)
    # Check specifically that the WARN level for verbose header was NOT called for 'Server'
    found_info = False
    for call in mock_addon._log_finding.call_args_list:
        if call.kwargs.get("finding_type") == "Passive Scan - Info Disclosure (Server)":
            assert call.kwargs.get("level") == "INFO"  # Expect INFO for generic server
            found_info = True
            break
    assert found_info, "Expected INFO log for generic Server header not found"


def test_caching_public_json(mock_addon, sample_url):
    """Test: Cache-Control: public on application/json."""
    headers = http.Headers(
        Cache_Control="public, max-age=86400", Content_Type="application/json"
    )
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Potential Sensitive Data Caching",
        url=sample_url,
        detail="'Cache-Control: public' found on potentially sensitive content type 'application/json'.",
        evidence=pytest.approx(dict),
    )


def test_caching_no_store_missing_json(mock_addon, sample_url):
    """Test: Caching not explicitly disabled on JSON (INFO level)."""
    headers = http.Headers(
        Content_Type="application/json", Cache_Control="max-age=60"
    )  # No no-store/no-cache
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="INFO",
        finding_type="Passive Scan - Caching Not Explicitly Disabled?",
        url=sample_url,
        detail="Caching not explicitly disabled (no-cache/no-store) on potentially sensitive content type 'application/json'. Review caching policy.",
        evidence=pytest.approx(dict),
    )


def test_cors_wildcard(mock_addon, sample_url):
    """Test: ACAO is wildcard (*)."""
    headers = http.Headers(Access_Control_Allow_Origin="*")
    check_security_headers(headers, sample_url, mock_addon)
    mock_addon._log_finding.assert_any_call(
        level="WARN",
        finding_type="Passive Scan - Permissive CORS (Wildcard)",
        url=sample_url,
        detail="Access-Control-Allow-Origin is wildcard (*), allowing read access from any origin.",
        evidence={"ACAO": "*", "ACAC": None},
    )


# End of tests/test_passive_headers.py
