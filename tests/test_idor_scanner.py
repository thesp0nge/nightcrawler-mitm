# tests/test_idor_scanner.py
import pytest
import httpx
import respx
import re
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

UUID_ALICE = "550e8400-e29b-41d4-a716-446655440000"
UUID_BOB = "661f9511-f30c-52e5-b827-557766551111"

@pytest.mark.asyncio
@respx.mock
async def test_idor_similarity_hit(mock_addon, target_info_get):
    """Test: Detects IDOR when the page structure is similar."""
    target_info_get["url"] = TARGET_URL
    target_info_get["params"] = {TARGET_PARAM: ORIGINAL_VALUE}

    # Use larger bodies to make ratio calculation more stable
    original_html = "<html><body><h1>User Profile: Alice</h1><p>Email: alice@test.com</p><div id='meta'>Data: 12345</div></body></html>"
    fuzzed_html = "<html><body><h1>User Profile: Bob</h1><p>Email: bob@test.com</p><div id='meta'>Data: 12345</div></body></html>"

    def idor_side_effect(request):
        url_str = str(request.url)
        if TARGET_IDOR_VALUE in url_str:
            return httpx.Response(200, text=fuzzed_html)
        return httpx.Response(200, text=original_html)

    respx.route(url=re.compile(r".*")).side_effect = idor_side_effect

    scanner = IDORScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called

@pytest.mark.asyncio
@respx.mock
async def test_idor_uuid_swap(mock_addon, target_info_get):
    """Test: Detects IDOR by swapping UUIDs discovered in other requests."""
    target_info_get["url"] = "http://test.com/api/user"
    target_info_get["params"] = {"uid": UUID_ALICE}
    mock_addon.discovered_ids = {UUID_ALICE, UUID_BOB}

    # Make JSON strings more similar to stay within 0.6 - 0.999 range
    alice_json = '{"user": {"name": "Alice", "role": "user", "id": "' + UUID_ALICE + '", "active": true}}'
    bob_json   = '{"user": {"name": "Bob",   "role": "user", "id": "' + UUID_BOB + '",   "active": true}}'

    def uuid_side_effect(request):
        url_str = str(request.url)
        if UUID_BOB in url_str:
            return httpx.Response(200, text=bob_json)
        return httpx.Response(200, text=alice_json)

    respx.route(url=re.compile(r".*")).side_effect = uuid_side_effect

    scanner = IDORScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    assert "Advanced Swap" in kwargs["finding_type"]
