# tests/test_active_open_redirect.py
import pytest
import respx
import httpx
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.open_redirect import OpenRedirectScanner
except ImportError:
    pytest.fail("Could not import OpenRedirectScanner", pytrace=False)

pytestmark = pytest.mark.asyncio

# Fixtures mock_addon and target_info_get are loaded from conftest.py

@respx.mock
async def test_open_redirect_found(mock_addon, target_info_get):
    """Test: Detects an open redirect when the injected URL is reflected in Location header."""
    target_info_get["params"]["next"] = "http://legitimate.com/continue"
    original_url = target_info_get["url"]

    test_redirect_url = "https://nightcrawler.test/redirect_test"
    respx.get(original_url, params={"query": "test", "next": test_redirect_url}).respond(
        302, headers={"Location": test_redirect_url}
    )

    scanner = OpenRedirectScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["finding_type"] == "Open Redirect Found"

@respx.mock
async def test_open_redirect_not_found_no_redirect(mock_addon, target_info_get):
    """Test: No finding if no redirect occurs."""
    target_info_get["params"]["next"] = "http://legitimate.com/continue"
    original_url = target_info_get["url"]
    test_redirect_url = "https://nightcrawler.test/redirect_test"

    respx.get(original_url, params={"query": "test", "next": test_redirect_url}).respond(
        200, text="No redirect here"
    )

    scanner = OpenRedirectScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_not_called()
