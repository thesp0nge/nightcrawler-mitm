# tests/test_active_open_redirect.py
import pytest
import respx
import httpx
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.open_redirect import scan_open_redirect
except ImportError:
    pytest.fail("Could not import scan_open_redirect", pytrace=False)

pytestmark = pytest.mark.asyncio

# Fixtures mock_addon and target_info_get are loaded from conftest.py


@respx.mock
async def test_open_redirect_found(mock_addon, target_info_get):
    """Test: Detects an open redirect when the injected URL is reflected in Location header."""
    # Setup target_info with a parameter that looks like a URL
    target_info_get["params"]["next"] = "http://legitimate.com/continue"
    original_url = target_info_get["url"]

    # Mock the HTTP response for the injected payload
    test_redirect_url = "https://nightcrawler.test/redirect_test"
    respx.get(original_url, params={"query": "test", "next": test_redirect_url}).respond(
        302, headers={"Location": test_redirect_url}
    )

    await scan_open_redirect(
        target_info_get, {}, httpx.AsyncClient(), mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="Open Redirect Found",
        url=original_url,
        detail=f"Parameter 'next' redirects to '{test_redirect_url}' (injected: '{test_redirect_url}')",
        evidence={
            "param": "next",
            "injected_url": test_redirect_url,
            "redirected_to": test_redirect_url,
            "status_code": 302,
        },
    )


@respx.mock
async def test_open_redirect_not_found_no_redirect(mock_addon, target_info_get):
    """Test: No finding if no redirect occurs."""
    target_info_get["params"]["next"] = "http://legitimate.com/continue"
    original_url = target_info_get["url"]
    test_redirect_url = "https://nightcrawler.test/redirect_test"

    # Mock the HTTP response to be a 200 OK, no redirect
    respx.get(original_url, params={"query": "test", "next": test_redirect_url}).respond(
        200, text="No redirect here"
    )

    await scan_open_redirect(
        target_info_get, {}, httpx.AsyncClient(), mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_not_called()


@respx.mock
async def test_open_redirect_not_found_to_other_domain(mock_addon, target_info_get):
    """Test: No finding if redirect is to an unexpected domain."""
    target_info_get["params"]["next"] = "http://legitimate.com/continue"
    original_url = target_info_get["url"]
    test_redirect_url = "https://nightcrawler.test/redirect_test"
    
    # Mock redirect to a different, non-injected URL
    respx.get(original_url, params={"query": "test", "next": test_redirect_url}).respond(
        302, headers={"Location": "http://some-other-domain.com"}
    )

    await scan_open_redirect(
        target_info_get, {}, httpx.AsyncClient(), mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_not_called()


@respx.mock
async def test_open_redirect_not_found_non_url_param(mock_addon, target_info_get):
    """Test: No finding if parameter does not look like a URL."""
    target_info_get["params"]["id"] = "123" # Not a URL
    original_url = target_info_get["url"]
    test_redirect_url = "https://nightcrawler.test/redirect_test"

    # Mock the HTTP response (shouldn't even be called with test_redirect_url)
    respx.get(original_url, params={"query": "test", "id": "123"}).respond(200)

    await scan_open_redirect(
        target_info_get, {}, httpx.AsyncClient(), mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_not_called()