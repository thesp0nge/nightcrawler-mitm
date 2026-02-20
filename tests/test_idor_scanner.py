# tests/test_idor_scanner.py
import pytest
import httpx
import respx
from unittest.mock import MagicMock
try:
    from nightcrawler.active_scans.idor_scanner import IDORScanner
except ImportError:
    pytest.fail("Could not import IDORScanner", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL = "http://test.com/user/profile"
TARGET_PARAM = "id"
ORIGINAL_VALUE = "101"
TARGET_IDOR_VALUE = "102"

@pytest.mark.asyncio
@respx.mock
async def test_idor_similarity_hit(mock_addon, target_info_get):
    """Test: Detects IDOR when the page structure is similar."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    original_html = "<html><body><h1>User Profile: Alice</h1><p>Email: alice@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    fuzzed_html = "<html><body><h1>User Profile: Bob</h1><p>Email: bob@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: TARGET_IDOR_VALUE}).respond(200, text=fuzzed_html)

    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    scanner = IDORScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert "Similarity Ratio" in kwargs["detail"]
    assert kwargs["confidence"] == "MEDIUM"

@pytest.mark.asyncio
@respx.mock
async def test_idor_dissimilarity_ignored(mock_addon, target_info_get):
    """Test: Ignores IDOR if the fuzzed response is too different."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    original_html = "<html><body><h1>User Profile: Alice</h1><p>Email: alice@test.com</p></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    login_html = "<html><head><title>Login</title></head><body><form>User:<input name='u'></form></body></html>"
    respx.get(TARGET_URL, params={TARGET_PARAM: TARGET_IDOR_VALUE}).respond(200, text=login_html)

    respx.get(TARGET_URL, params={TARGET_PARAM: ORIGINAL_VALUE}).respond(200, text=original_html)

    scanner = IDORScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_not_called()
