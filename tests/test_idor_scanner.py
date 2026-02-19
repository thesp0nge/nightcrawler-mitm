# tests/test_idor_scanner.py
import pytest
import httpx
import respx
import difflib
from unittest.mock import MagicMock
from nightcrawler.idor_scanner import scan_idor

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL = "http://test.com/user/profile"
TARGET_PARAM = "id"
# Use a numeric value as required by IDOR scanner
ORIGINAL_VALUE = "101"
TARGET_IDOR_VALUE = "102"

# Fixtures mock_addon and target_info_get are loaded from conftest.py

@pytest.mark.asyncio
@respx.mock
async def test_idor_similarity_hit(mock_addon, target_info_get):
    """Test: Detects IDOR when the page structure is similar but content length differs."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    # 1. Original response (Ratio 1.0)
    original_html = "<html><body><h1>User Profile: Alice</h1><p>Email: alice@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    # 2. Fuzzed response (Ratio ~0.9, same structure, different data)
    fuzzed_html = "<html><body><h1>User Profile: Bob</h1><p>Email: bob@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: TARGET_IDOR_VALUE}).respond(200, text=fuzzed_html)

    # Stability check (fetch original again)
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    await scan_idor(
        target_info_get,
        {},
        httpx.AsyncClient(),
        mock_addon,
        MagicMock()
    )

    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    assert "Similarity Ratio" in args[3]
    assert kwargs["confidence"] == "MEDIUM"


@pytest.mark.asyncio
@respx.mock
async def test_idor_dissimilarity_ignored(mock_addon, target_info_get):
    """Test: Ignores IDOR if the fuzzed response is too different (e.g., login redirect/error)."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    # Original response
    original_html = "<html><body><h1>User Profile: Alice</h1><p>Email: alice@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    # Fuzzed response is a login page (Completely different structure, Ratio < 0.6)
    login_html = "<html><head><title>Login</title></head><body><form>User:<input name='u'></form></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: TARGET_IDOR_VALUE}).respond(200, text=login_html)

    # Stability check (original stays the same)
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    await scan_idor(
        target_info_get,
        {},
        httpx.AsyncClient(),
        mock_addon,
        MagicMock()
    )

    # Ratio should be low, so no finding should be logged.
    mock_addon._log_finding.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_idor_unstable_page_ignored(mock_addon, target_info_get):
    """Test: Ignores IDOR if the original page itself is unstable."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    original_html = "<html><body><h1>User Profile: Alice</h1><p>Time: 12:00:00</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    # Fuzzed response
    fuzzed_html = "<html><body><h1>User Profile: Bob</h1><p>Time: 12:00:01</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: TARGET_IDOR_VALUE}).respond(200, text=fuzzed_html)

    # Stability check returns DIFFERENT html (time changed, or random content)
    unstable_html = "<html><body><h1>Something Else</h1><p>Random: 99823</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=unstable_html)

    await scan_idor(
        target_info_get,
        {},
        httpx.AsyncClient(),
        mock_addon,
        MagicMock()
    )

    mock_addon._log_finding.assert_not_called()
