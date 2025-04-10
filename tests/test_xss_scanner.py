# tests/test_xss_scanner.py
# Unit tests for the XSS scanner functions using pytest and mocks.

import pytest
import httpx
import html  # <-- IMPORT ADDED
from unittest.mock import (
    MagicMock,
    call,
)  # Using unittest.mock integrated with pytest via mocker

# Import the functions to test
try:
    from nightcrawler.xss_scanner import (
        scan_xss_reflected_basic,
        scan_xss_stored_inject,
    )
except ImportError as e:
    # This might happen if path isn't set correctly when running pytest directly sometimes
    # Or if there's still an import error within xss_scanner itself
    pytest.fail(f"Failed to import scanner functions: {e}", pytrace=False)


# --- Mark all tests in this module as asyncio ---
pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL_GET = "http://test.com/search"
TARGET_URL_POST = "http://test.com/comment"
TARGET_PARAM_GET = "query"
TARGET_PARAM_POST = "comment"

DEFAULT_COOKIES = {}
DEFAULT_HEADERS = {"User-Agent": "Test Browser"}

# Use a consistent list for reflected tests
REFLECTED_PAYLOADS = [
    "<script>alert('XSSR1')</script>",  # Payload 1
    "'\"><svg/onload=alert('XSSR2')>",  # Payload 2
]
STORED_PREFIX = "testNC"
# Use a format for stored tests that doesn't conflict with potential UI rendering
STORED_FORMAT = "[[probe_id:{probe_id}]]"

# --- Fixtures ---


@pytest.fixture
def mock_addon(mocker):
    """Pytest fixture to create a mock MainAddon instance."""
    instance = mocker.MagicMock(name="MainAddonInstance")
    instance._log_finding = mocker.MagicMock(name="_log_finding")
    instance.register_injection = mocker.MagicMock(name="register_injection")
    # Reset mocks automatically before each test that uses this fixture
    mocker.resetall()
    yield instance  # Provide the instance to the test
    # mocker.resetall() # Alternatively reset after, but before is safer usually


@pytest.fixture
def target_info_get():
    """Target info dictionary for a GET request with one parameter."""
    return {
        "url": f"{TARGET_URL_GET}?{TARGET_PARAM_GET}=test",
        "method": "GET",
        "params": {TARGET_PARAM_GET: "test"},  # Parsed query params
        "data": {},  # No form data for GET
        "headers": DEFAULT_HEADERS,
        "cookies": DEFAULT_COOKIES,
    }


@pytest.fixture
def target_info_post():
    """Target info dictionary for a POST request with one parameter."""
    return {
        "url": TARGET_URL_POST,
        "method": "POST",
        "params": {},  # No query params
        "data": {TARGET_PARAM_POST: "safe comment"},  # Parsed form data
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            **DEFAULT_HEADERS,
        },
        "cookies": DEFAULT_COOKIES,
    }


# --- Tests for scan_xss_reflected_basic ---


@pytest.mark.asyncio
async def test_reflected_exact_hit(httpx_mock, mock_addon, target_info_get):
    """Test: Exact payload is reflected, should log ERROR once and break."""
    payload_hit = REFLECTED_PAYLOADS[0]  # <script>...
    # --- Mock only ONE response, as the break should prevent further requests ---
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={payload_hit}",  # Match exact URL with payload
        method="GET",
        text=f"<html><body>Search results: {payload_hit}</body></html>",  # Exact reflection
        status_code=200,
        headers={"Content-Type": "text/html"},
    )

    # Run the scanner function
    await scan_xss_reflected_basic(
        target_info=target_info_get,
        cookies=DEFAULT_COOKIES,
        http_client=httpx.AsyncClient(),  # httpx_mock intercepts this
        payloads=REFLECTED_PAYLOADS,  # Provide both payloads
        addon_instance=mock_addon,
    )

    # Assert: _log_finding was called exactly once with ERROR for the first payload
    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="XSS Found? (Reflected - Exact)",
        url=target_info_get["url"],
        detail=f"Param: {TARGET_PARAM_GET}, Payload Snippet: {payload_hit[:50]}...",
        evidence={"param": TARGET_PARAM_GET, "payload": payload_hit[:100]},
    )
    # Verify call count explicitly
    assert mock_addon._log_finding.call_count == 1


@pytest.mark.asyncio
async def test_reflected_escaped_hit(httpx_mock, mock_addon, target_info_get):
    """Test: Only HTML-escaped payload is reflected, should log INFO once."""
    payload_sent = REFLECTED_PAYLOADS[0]  # <script>...
    payload_escaped = html.escape(payload_sent, quote=True)  # &lt;script&gt;...

    # --- Mock TWO responses, one for each payload attempt ---
    # Mock response for the first payload (contains escaped, not exact)
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={payload_sent}",
        method="GET",
        text=f"<html><body>Search results: {payload_escaped}</body></html>",
        status_code=200,
        headers={"Content-Type": "text/html"},
    )
    # Mock response for the second payload (no reflection)
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={REFLECTED_PAYLOADS[1]}",
        method="GET",
        text="<html><body>Safe</body></html>",
        status_code=200,
        headers={"Content-Type": "text/html"},
    )

    # Run the scanner
    await scan_xss_reflected_basic(
        target_info_get,
        DEFAULT_COOKIES,
        httpx.AsyncClient(),
        REFLECTED_PAYLOADS,
        mock_addon,
    )

    # Assert: _log_finding was called exactly once with INFO level for escaped reflection
    mock_addon._log_finding.assert_called_once_with(
        level="INFO",
        finding_type="Passive Scan - Escaped Reflection Found",
        url=target_info_get["url"],
        detail=f"Input reflected but HTML-escaped. Param: {TARGET_PARAM_GET}, Payload Snippet: {payload_sent[:50]}...",
        evidence={"param": TARGET_PARAM_GET, "payload": payload_sent[:100]},
    )
    # Verify call count explicitly
    assert mock_addon._log_finding.call_count == 1


@pytest.mark.asyncio
async def test_reflected_no_hit(httpx_mock, mock_addon, target_info_get):
    """Test: Payload is not reflected at all, should not log."""
    # --- Mock TWO responses, one for each payload attempt, neither reflects ---
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={REFLECTED_PAYLOADS[0]}",
        method="GET",
        text="<html><body>Safe Output 1</body></html>",
        status_code=200,
        headers={"Content-Type": "text/html"},
    )
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={REFLECTED_PAYLOADS[1]}",
        method="GET",
        text="<html><body>Safe Output 2</body></html>",
        status_code=200,
        headers={"Content-Type": "text/html"},
    )

    # Run the scanner
    await scan_xss_reflected_basic(
        target_info_get,
        DEFAULT_COOKIES,
        httpx.AsyncClient(),
        REFLECTED_PAYLOADS,
        mock_addon,
    )

    # Assert: _log_finding was NOT called at all
    mock_addon._log_finding.assert_not_called()


@pytest.mark.asyncio
async def test_reflected_logs_only_first_hit(httpx_mock, mock_addon, target_info_get):
    """Test: If first payload hits exactly, subsequent payloads are not tested/logged."""
    payload1 = REFLECTED_PAYLOADS[0]
    # --- Mock only ONE response (for the first payload) - IT HITS ---
    httpx_mock.add_response(
        url=f"{TARGET_URL_GET}?{TARGET_PARAM_GET}={payload1}",
        method="GET",
        text=f"<html><body>Results: {payload1} exactly!</body></html>",  # Exact reflection
        status_code=200,
        headers={"Content-Type": "text/html"},
    )
    # No mock needed for payload2, because the 'break' should prevent the request

    # Run the scanner
    await scan_xss_reflected_basic(
        target_info_get,
        DEFAULT_COOKIES,
        httpx.AsyncClient(),
        REFLECTED_PAYLOADS,
        mock_addon,  # Pass both payloads
    )

    # Assert: _log_finding was called EXACTLY ONCE with ERROR level for payload1
    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="XSS Found? (Reflected - Exact)",
        url=target_info_get["url"],
        detail=f"Param: {TARGET_PARAM_GET}, Payload Snippet: {payload1[:50]}...",
        evidence={"param": TARGET_PARAM_GET, "payload": payload1[:100]},
    )
    assert mock_addon._log_finding.call_count == 1  # Explicit count check


# --- Tests for scan_xss_stored_inject ---


@pytest.mark.asyncio
async def test_stored_inject_registers_payload(
    httpx_mock, mock_addon, target_info_post
):
    """Test: Stored XSS injection attempt registers the correct probe details."""
    # Mock a generic successful response for the POST request
    httpx_mock.add_response(
        url=TARGET_URL_POST, method="POST", status_code=200, text="Comment submitted"
    )

    # Run the injection function
    await scan_xss_stored_inject(
        target_info=target_info_post,
        cookies=DEFAULT_COOKIES,
        http_client=httpx.AsyncClient(),
        addon_instance=mock_addon,
        probe_prefix=STORED_PREFIX,
        payload_format=STORED_FORMAT,
    )

    # Assert that register_injection was called once for the 'comment' parameter
    assert mock_addon.register_injection.call_count == 1
    # Get the arguments passed to the mock
    call_args, call_kwargs = mock_addon.register_injection.call_args
    # First positional argument is probe_id
    probe_id_arg = call_args[0]
    # Second positional argument is injection_details dictionary
    details_arg = call_args[1]

    # Check probe ID structure
    assert probe_id_arg.startswith(f"{STORED_PREFIX}_")
    assert TARGET_PARAM_POST in probe_id_arg  # Contains param name

    # Check details dictionary content
    assert details_arg["url"] == TARGET_URL_POST
    assert details_arg["param_name"] == TARGET_PARAM_POST
    assert details_arg["method"] == "POST"
    assert details_arg["probe_id"] == probe_id_arg
    # Check the actual *injected value* (original + payload) which should be stored
    expected_probe_str = STORED_FORMAT.format(probe_id=probe_id_arg)
    original_value = target_info_post["data"][TARGET_PARAM_POST]
    # This assertion relies on the fix made previously in scan_xss_stored_inject
    assert details_arg["payload_used"] == original_value + expected_probe_str


@pytest.mark.asyncio
async def test_stored_inject_skips_on_invalid_format(
    httpx_mock, mock_addon, target_info_post
):
    """Test: Injection is skipped and nothing registered if format string is invalid."""
    invalid_format = "This is wrong"  # Missing {probe_id}

    # Run the injection function with invalid format
    await scan_xss_stored_inject(
        target_info_post,
        DEFAULT_COOKIES,
        httpx.AsyncClient(),
        mock_addon,
        STORED_PREFIX,
        invalid_format,
    )

    # Assert register_injection was NEVER called
    mock_addon.register_injection.assert_not_called()
    # Assert _log_finding was also not called (as no finding occurs here)
    mock_addon._log_finding.assert_not_called()


# --- TODO: Add tests for Stored XSS *detection* ---
# (Requires mocking addon state and revisit worker flow)

# End of tests/test_xss_scanner.py
