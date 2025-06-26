# tests/test_active_traversal.py
# Unit tests for the Directory Traversal scanner logic.

import pytest
import httpx
import respx
import re
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.traversal import scan_directory_traversal
except ImportError:
    pytest.fail("Could not import scan_directory_traversal", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL_BASE = "http://test.com/files"
TARGET_PARAM = "file"
PASSWD_CONTENT = "root:x:0:0:root:/root:/bin/bash"
WIN_CONTENT = "[boot loader]"

# Fixtures are loaded from conftest.py


@pytest.mark.asyncio
@respx.mock
async def test_traversal_finds_passwd(mock_addon, target_info_vulnerable_param):
    """Test: Payload retrieves /etc/passwd content via GET request."""
    working_payload = "../../../etc/passwd"

    # --- Mock a GET request, not HEAD ---
    respx.get(TARGET_URL_BASE, params={TARGET_PARAM: working_payload}).respond(
        status_code=200, text=f"{PASSWD_CONTENT}\n"
    )
    # Fallback for other requests
    respx.route().respond(404)

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock()

    await scan_directory_traversal(
        target_info_vulnerable_param, {}, test_client, mock_addon, mock_logger
    )

    mock_addon._log_finding.assert_any_call(
        level="ERROR",
        finding_type="Directory Traversal? (Content Match)",
        evidence={
            "param": TARGET_PARAM,
            "payload": working_payload,
            "matched_pattern": "root:x:0:0",
        },
    )


@pytest.mark.asyncio
@respx.mock
async def test_traversal_finds_winini(mock_addon, target_info_vulnerable_param):
    """Test: Payload retrieves win.ini content via GET request."""
    working_payload = "..\\..\\windows/win.ini"

    # --- Mock a GET request, not HEAD ---
    respx.get(TARGET_URL_BASE, params={TARGET_PARAM: working_payload}).respond(
        status_code=200, text=f"; for 16-bit app support\n{WIN_CONTENT}\n"
    )
    respx.route().respond(404)  # Fallback

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock()

    await scan_directory_traversal(
        target_info_vulnerable_param, {}, test_client, mock_addon, mock_logger
    )

    # Find the specific call to be more robust
    found_call = False
    for call in mock_addon._log_finding.call_args_list:
        if call.kwargs.get("finding_type") == "Directory Traversal? (Content Match)":
            assert r"\[boot loader\]" in call.kwargs.get("evidence", {}).get(
                "matched_pattern", ""
            )
            found_call = True
            break
    assert found_call, "Expected ERROR log for Directory Traversal (win.ini) not found"


@pytest.mark.asyncio
@respx.mock
async def test_traversal_no_hit(mock_addon, target_info_vulnerable_param):
    """Test: Traversal payloads are sent, but no sensitive content is found."""
    # Mock all GET requests to return normal content
    respx.route(method="GET").respond(200, text="<html>Normal page</html>")

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock()

    await scan_directory_traversal(
        target_info_vulnerable_param, {}, test_client, mock_addon, mock_logger
    )

    mock_addon._log_finding.assert_not_called()
