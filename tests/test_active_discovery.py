# tests/test_active_discovery.py
# Unit tests for the Content Discovery active scanner.

import pytest
import httpx
import respx
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.discovery import scan_content_discovery
    from nightcrawler.addon import MainAddon
except ImportError:
    pytest.fail("Could not import scan_content_discovery or MainAddon", pytrace=False)

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

    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="Content Discovery - File/Dir Found",
        url=target_url,
        detail="Found accessible resource with status code 200.",
        evidence={"status_code": 200, "wordlist_item": found_file},
    )


@pytest.mark.asyncio
@respx.mock
async def test_discovery_finds_403_forbidden(mock_addon):
    """Test: Finds a sensitive directory with a 403 Forbidden response."""
    found_dir = "admin/"
    target_url = f"{TARGET_URL_BASE}{found_dir}"

    # Correct mock order: specific first, then fallback
    respx.head(target_url).respond(status_code=403)
    respx.route(method="HEAD").respond(404)

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock()

    await scan_content_discovery(
        TARGET_URL_BASE, DEFAULT_WORDLIST, {}, test_client, mock_addon, mock_logger
    )

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Content Discovery - Interesting Status 403",
        url=target_url,
        detail="Found accessible resource with status code 403.",
        evidence={"status_code": 403, "wordlist_item": found_dir},
    )


@pytest.mark.asyncio
@respx.mock
async def test_discovery_ignores_404(mock_addon):
    """Test: Does not log findings for 404 Not Found responses."""
    # Mock all HEAD requests to return 404
    respx.route(method="HEAD").respond(404)

    test_client = httpx.AsyncClient(follow_redirects=False)
    mock_logger = MagicMock()

    await scan_content_discovery(
        TARGET_URL_BASE, DEFAULT_WORDLIST, {}, test_client, mock_addon, mock_logger
    )

    mock_addon._log_finding.assert_not_called()
