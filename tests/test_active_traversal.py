# tests/test_active_traversal.py
# Unit tests for the Directory Traversal scanner logic using respx for mocking.

import pytest
import httpx
import re  # Needed for regex matching in respx routes
import respx  # Use respx directly for mocking
from unittest.mock import MagicMock, call

# Import the function to test
try:
    # Ensure this import path is correct based on your project structure
    from nightcrawler.active_scans.traversal import scan_directory_traversal
except ImportError as e:
    pytest.fail(f"Could not import scan_directory_traversal: {e}", pytrace=False)

# Mark all tests in this module as asyncio
pytestmark = pytest.mark.asyncio

# --- Test Data (Unchanged) ---
TARGET_URL_BASE = "http://test.com/files"
TARGET_PARAM = "file"
DEFAULT_COOKIES = {}  # Note: Cookies dict passed to scanner, but sent via header by scanner logic
DEFAULT_HEADERS = {"User-Agent": "Test"}
PASSWD_CONTENT = "root:x:0:0:root:/root:/bin/bash"
WIN_CONTENT = "[boot loader]"

# --- Fixtures (Unchanged except removing non_assertive_httpx) ---


@pytest.fixture
def mock_addon(mocker):
    """Mock MainAddon instance with mockable logging/registration methods."""
    instance = mocker.MagicMock(name="MainAddonInstance")
    instance._log_finding = mocker.MagicMock(name="_log_finding")
    instance.register_injection = mocker.MagicMock(
        name="register_injection"
    )  # Keep if other scanners tested here
    mocker.resetall()  # Reset mocks before each test
    return instance


@pytest.fixture
def target_info_vulnerable_param():
    """Target info with a parameter name ('file') likely vulnerable."""
    return {
        "url": f"{TARGET_URL_BASE}?{TARGET_PARAM}=report.txt",
        "method": "GET",
        "params": {TARGET_PARAM: "report.txt"},
        "data": {},
        "headers": DEFAULT_HEADERS,
        "cookies": DEFAULT_COOKIES,
    }


@pytest.fixture
def target_info_other_param():
    """Target info with a parameter name ('id') that IS considered suspicious."""
    return {
        "url": f"{TARGET_URL_BASE}?id=123&action=view",
        "method": "GET",
        "params": {"id": "123", "action": "view"},
        "data": {},
        "headers": DEFAULT_HEADERS,
        "cookies": DEFAULT_COOKIES,
    }


# --- Test Cases (Using respx) ---


@pytest.mark.asyncio
@respx.mock  # Use respx mock decorator
async def test_traversal_finds_passwd(mock_addon, target_info_vulnerable_param):
    """Test: Payload retrieves /etc/passwd content (using respx)."""
    working_payload = "../../../etc/passwd"
    # Construct the exact URL the scanner should request for the successful payload
    expected_url = f"{TARGET_URL_BASE}?{TARGET_PARAM}={working_payload}"

    # --- Mocking with respx ---
    # 1. Specific route for the successful payload (matched first)
    respx.get(expected_url).respond(
        status_code=200, text=f"Some junk before\n{PASSWD_CONTENT}\nSome junk after"
    )
    # 2. Fallback route for *any other* GET request to the same base path, returning 404
    # This catches all other unsuccessful payload attempts by the scanner.
    fallback_pattern = (
        rf"^{re.escape(TARGET_URL_BASE)}\?.*"  # Regex for any query string
    )
    respx.get(url__regex=fallback_pattern).respond(404, text="Not Found")
    # -----------------------

    # Run the scanner function (passing an empty dict for cookies as example)
    await scan_directory_traversal(
        target_info=target_info_vulnerable_param,
        cookies={},  # Scanner expects dict, but sends via header
        http_client=httpx.AsyncClient(),  # respx intercepts this client
        addon_instance=mock_addon,
    )

    # --- Assertions (remain the same) ---
    # Check that _log_finding was called with the expected arguments for the vulnerability
    found_call = False
    for call in mock_addon._log_finding.call_args_list:
        kwargs = call.kwargs
        if kwargs.get("finding_type") == "Directory Traversal? (Content Match)":
            assert kwargs.get("level") == "ERROR"
            assert kwargs.get("evidence", {}).get("payload") == working_payload
            # Check if the pattern matched is the passwd one
            assert "root:x:0:0" in kwargs.get("evidence", {}).get("matched_pattern", "")
            found_call = True
            break  # Stop after finding the expected call
    assert found_call, "Expected ERROR log for Directory Traversal (passwd) not found"


@pytest.mark.asyncio
@respx.mock  # Use respx mock decorator
async def test_traversal_finds_winini(mock_addon, target_info_vulnerable_param):
    """Test: Payload retrieves win.ini content (using respx)."""
    working_payload = "..\\..\\windows/win.ini"  # Example payload
    expected_url = f"{TARGET_URL_BASE}?{TARGET_PARAM}={working_payload}"

    # --- Mocking with respx ---
    # 1. Specific hit for win.ini payload
    respx.get(expected_url).respond(
        status_code=200, text=f"; comment\n{WIN_CONTENT}\nmore stuff"
    )
    # 2. Fallback for other requests to the endpoint
    fallback_pattern = rf"^{re.escape(TARGET_URL_BASE)}\?{re.escape(TARGET_PARAM)}=.*"
    respx.get(url__regex=fallback_pattern).respond(404)
    # ------------------------

    await scan_directory_traversal(
        target_info_vulnerable_param, {}, httpx.AsyncClient(), mock_addon
    )

    # --- Assertions (remain the same) ---
    found_call = False
    for call in mock_addon._log_finding.call_args_list:
        kwargs = call.kwargs
        if kwargs.get("finding_type") == "Directory Traversal? (Content Match)":
            assert kwargs.get("level") == "ERROR"
            assert kwargs.get("evidence", {}).get("payload") == working_payload
            # Check if the pattern matched is the win.ini one
            assert r"\[boot loader\]" in kwargs.get("evidence", {}).get(
                "matched_pattern", ""
            )
            found_call = True
            break
    assert found_call, "Expected ERROR log for Directory Traversal (win.ini) not found"


@pytest.mark.asyncio
@respx.mock  # Use respx mock decorator
async def test_traversal_no_vuln_param(mock_addon, target_info_other_param):
    """Test: Scanner attempts fuzzing 'id' param, but mock returns no findings (using respx)."""
    # --- Mocking Strategy ---
    # The scanner *will* try payloads on the 'id' parameter.
    # We need a fallback mock to catch these requests and return a non-vulnerable response.
    fallback_pattern = (
        rf"^{re.escape(TARGET_URL_BASE)}\?id=.*"  # Match requests fuzzing 'id'
    )
    respx.get(url__regex=fallback_pattern).respond(404, text="Not Found or Normal Page")
    # Also mock the original request URL in case it's re-requested? Unlikely needed here.
    # respx.get(target_info_other_param['url']).respond(200, text="Original page")
    # ------------------------

    await scan_directory_traversal(
        target_info_other_param, {}, httpx.AsyncClient(), mock_addon
    )

    # Assert _log_finding was not called (no vulnerabilities expected)
    mock_addon._log_finding.assert_not_called()


@pytest.mark.asyncio
@respx.mock  # Use respx mock decorator
async def test_traversal_no_hit(mock_addon, target_info_vulnerable_param):
    """Test: Traversal payloads are sent, but no sensitive content is found (using respx)."""
    # --- Mocking Strategy ---
    # Provide a default/fallback response for all requests made by the scanner to the 'file' param
    fallback_pattern = rf"^{re.escape(TARGET_URL_BASE)}\?{re.escape(TARGET_PARAM)}=.*"
    respx.get(url__regex=fallback_pattern).respond(
        status_code=200,  # Or 404
        text="<html><body>Normal file content or Not Found</body></html>",
    )
    # ------------------------

    await scan_directory_traversal(
        target_info_vulnerable_param, {}, httpx.AsyncClient(), mock_addon
    )

    # Assert no ERROR level findings were logged
    for call in mock_addon._log_finding.call_args_list:
        assert call.kwargs.get("level") != "ERROR"
        assert "Directory Traversal?" not in call.kwargs.get("finding_type", "")
    # If absolutely no logs are expected (not even INFO/WARN from potential errors):
    # mock_addon._log_finding.assert_not_called()


# End of tests/test_active_traversal.py
