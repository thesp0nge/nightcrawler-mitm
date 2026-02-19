# tests/test_xss_scanner.py
import pytest
import httpx
import html
import respx
from unittest.mock import MagicMock

try:
    from nightcrawler.xss_scanner import (
        scan_xss_reflected_basic,
        scan_xss_stored_inject,
    )
except ImportError as e:
    pytest.fail(f"Could not import xss scanner functions: {e}", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL_GET = "http://test.com/search"
TARGET_URL_POST = "http://test.com/comment"
TARGET_PARAM_GET = "query"
TARGET_PARAM_POST = "comment"
REFLECTED_PAYLOADS = [
    "<script>alert('XSSR1')</script>",
    "'\"><svg/onload=alert('XSSR2')>",
]
STORED_PREFIX = "testNC"
STORED_FORMAT = "[[probe_id:{probe_id}]]"

# Fixtures are now loaded automatically from conftest.py

# --- Test Cases ---


@pytest.mark.asyncio
@respx.mock
async def test_reflected_exact_hit(mock_addon, target_info_get):
    """Test: Exact payload is reflected, should log ERROR once."""
    payload_hit = REFLECTED_PAYLOADS[0]

    # Mock the specific request that is expected to HIT
    respx.get(TARGET_URL_GET, params={TARGET_PARAM_GET: payload_hit}).respond(
        200, headers={"Content-Type": "text/html"}, text=f"<html>{payload_hit}</html>"
    )
    # The scanner should break after this hit, so no fallback mock is needed for other payloads

    await scan_xss_reflected_basic(
        target_info_get,
        {},
        httpx.AsyncClient(follow_redirects=False),
        REFLECTED_PAYLOADS,
        mock_addon,
        MagicMock(),
    )

    mock_addon._log_finding.assert_called_once()

    # --- CORRECTED ASSERTION: Access positional args via .args tuple ---
    args, kwargs = mock_addon._log_finding.call_args
    assert args[0] == "ERROR"  # level
    assert args[1] == "XSS Found? (Reflected - Exact)"  # finding_type
    assert args[2] == target_info_get["url"]  # url
    # --------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_reflected_escaped_hit(mock_addon, target_info_get):
    """Test: Only HTML-escaped payload is reflected, should log INFO once."""
    payload_sent = REFLECTED_PAYLOADS[0]
    payload_escaped = html.escape(payload_sent, quote=True)

    # Mock the request for the first payload to return the ESCAPED version
    respx.get(TARGET_URL_GET, params={TARGET_PARAM_GET: payload_sent}).respond(
        200,
        headers={"Content-Type": "text/html"},
        text=f"<html>{payload_escaped}</html>",
    )
    # Mock the request for the second payload to return a safe response
    respx.get(TARGET_URL_GET, params={TARGET_PARAM_GET: REFLECTED_PAYLOADS[1]}).respond(
        200, headers={"Content-Type": "text/html"}, text="Safe"
    )

    await scan_xss_reflected_basic(
        target_info_get,
        {},
        httpx.AsyncClient(follow_redirects=False),
        REFLECTED_PAYLOADS,
        mock_addon,
        MagicMock(),
    )

    mock_addon._log_finding.assert_called_once()
    # --- CORRECTED ASSERTION: Access positional args via .args tuple ---
    args, kwargs = mock_addon._log_finding.call_args
    assert args[0] == "INFO"  # level
    assert args[1] == "Passive Scan - Escaped Reflection Found"  # finding_type
    # --------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_reflected_no_hit(mock_addon, target_info_get):
    """Test: Payload is not reflected at all, should not log."""
    # Mock all potential requests to return a safe, non-reflecting response
    respx.route(method="GET", host="test.com").respond(
        200, text="<html>Safe Output</html>"
    )

    await scan_xss_reflected_basic(
        target_info_get,
        {},
        httpx.AsyncClient(follow_redirects=False),
        REFLECTED_PAYLOADS,
        mock_addon,
        MagicMock(),
    )

    mock_addon._log_finding.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_reflected_logs_only_first_hit(mock_addon, target_info_get):
    """Test: If first payload hits exactly, subsequent payloads are not tested/logged."""
    payload1 = REFLECTED_PAYLOADS[0]
    # Mock only the FIRST payload's request to succeed.
    respx.get(TARGET_URL_GET, params={TARGET_PARAM_GET: payload1}).respond(
        200, headers={"Content-Type": "text/html"}, text=f"Results: {payload1} exactly!"
    )
    # respx will raise an error if an unmocked request is made, which proves our 'break' logic works.

    await scan_xss_reflected_basic(
        target_info_get,
        {},
        httpx.AsyncClient(follow_redirects=False),
        REFLECTED_PAYLOADS,
        mock_addon,
        MagicMock(),
    )

    # The assertion is simply that it was called once.
    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    assert args[0] == "ERROR"  # Check level of the single call


@pytest.mark.asyncio
@respx.mock
async def test_stored_inject_registers_payload(mock_addon, target_info_post):
    """Test: Stored XSS injection attempt registers the correct probe details."""
    # Mock a generic successful response for the POST request
    respx.post(TARGET_URL_POST).respond(200, text="Comment submitted")

    await scan_xss_stored_inject(
        target_info=target_info_post,
        cookies={},
        http_client=httpx.AsyncClient(follow_redirects=False),
        addon_instance=mock_addon,
        probe_prefix=STORED_PREFIX,
        payload_format=STORED_FORMAT,
        logger=MagicMock(),
    )

    mock_addon.register_injection.assert_called_once()

    # --- CORRECTED ASSERTION: Access positional args via .args tuple ---
    args, kwargs = mock_addon.register_injection.call_args
    assert kwargs == {}
    probe_id_arg = args[0]
    details_arg = args[1]
    # --------------------------------------------------------------------

    # Check the details of the registered injection
    assert probe_id_arg.startswith(f"{STORED_PREFIX}_")
    assert details_arg["url"] == TARGET_URL_POST
    assert details_arg["param_name"] == TARGET_PARAM_POST
    assert details_arg["probe_id"] == probe_id_arg

    expected_probe_str = STORED_FORMAT.format(probe_id=probe_id_arg)
    original_value = target_info_post["data"][TARGET_PARAM_POST]
    assert details_arg["payload_used"] == original_value + expected_probe_str


@pytest.mark.asyncio
@respx.mock
async def test_stored_inject_skips_on_invalid_format(mock_addon, target_info_post):
    """Test: Injection is skipped if format string is invalid."""
    invalid_format = "This is wrong"  # Missing {probe_id}

    await scan_xss_stored_inject(
        target_info_post,
        {},
        httpx.AsyncClient(follow_redirects=False),
        mock_addon,
        STORED_PREFIX,
        invalid_format,
        MagicMock(),
    )

    # Assert register_injection was NEVER called
    mock_addon.register_injection.assert_not_called()
