# tests/test_active_discovery.py
# Unit tests for the Content Discovery active scanner.

import pytest
import httpx
import respx
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.discovery import scan_content_discovery, ContentDiscoveryScanner
except ImportError:
    pytest.fail("Could not import scan_content_discovery or ContentDiscoveryScanner", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL_BASE = "http://test.com/app/"
DEFAULT_WORDLIST = {".env", "admin/"}
DEFAULT_COOKIES = {}

# --- Fixtures are loaded from conftest.py ---

@pytest.mark.asyncio
@respx.mock
async def test_discovery_finds_200_ok(mock_addon):
    """Test: Finds a sensitive file with a 200 OK response."""
    found_file = ".env"
    target_url = f"{TARGET_URL_BASE}{found_file}"

    # 1. Mock the specific successful response (takes precedence)
    respx.head(target_url).respond(status_code=200)
    # 2. Mock a generic fallback for any other unmocked HEAD request
    respx.route(method="HEAD").respond(404)

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock(spec=["debug", "info", "warn", "error"])

    await scan_content_discovery(
        base_dir_url=TARGET_URL_BASE,
        wordlist=DEFAULT_WORDLIST,
        cookies=DEFAULT_COOKIES,
        http_client=test_client,
        addon_instance=mock_addon,
        logger=mock_logger,
    )

    mock_addon._log_finding.assert_called_once()

@pytest.mark.asyncio
@respx.mock
async def test_discovery_class_run(mock_addon, target_info_get):
    """Test: ContentDiscoveryScanner correctly extracts base dir and runs."""
    mock_addon.discovery_wordlist = {".git/config"}
    target_info_get["url"] = "http://test.com/app/index.php"
    expected_probe_url = "http://test.com/app/.git/config"
    
    respx.head(expected_probe_url).respond(status_code=200)
    respx.route(method="HEAD").respond(404)

    scanner = ContentDiscoveryScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_called_once()
    args, kwargs = mock_addon._log_finding.call_args
    # ContentDiscoveryScanner uses keyword arguments
    assert "Content Discovery" in kwargs["finding_type"]
    assert kwargs["url"] == expected_probe_url
