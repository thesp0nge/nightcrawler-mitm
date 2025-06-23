# tests/test_active_discovery.py
import pytest
import httpx
import respx
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.discovery import scan_content_discovery
except ImportError:
    pytest.fail("Could not import scan_content_discovery", pytrace=False)

pytestmark = pytest.mark.asyncio

TARGET_URL_BASE = "http://test.com/app/"
DEFAULT_WORDLIST = {".env", "admin/"}


@pytest.mark.asyncio
@respx.mock
async def test_discovery_finds_200_ok(mock_addon):
    """Test: Finds a sensitive file with a 200 OK response."""
    found_file = ".env"
    # Mock the specific request that should be found
    respx.head(f"{TARGET_URL_BASE}{found_file}").respond(status_code=200)
    # Mock a generic fallback for any other unmocked HEAD request
    respx.route(method="HEAD").respond(404)

    test_client = httpx.AsyncClient(follow_redirects=False)
    await scan_content_discovery(
        TARGET_URL_BASE, DEFAULT_WORDLIST, {}, test_client, mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="Content Discovery - File/Dir Found",
        url=f"{TARGET_URL_BASE}{found_file}",
        detail="Found accessible resource with status code 200.",
        evidence={"status_code": 200, "wordlist_item": found_file},
    )


@pytest.mark.asyncio
@respx.mock
async def test_discovery_finds_403_forbidden(mock_addon):
    """Test: Finds a sensitive directory with a 403 Forbidden response."""
    found_dir = "admin/"
    respx.head(f"{TARGET_URL_BASE}{found_dir}").respond(status_code=403)
    respx.route(method="HEAD").respond(404)  # Fallback

    test_client = httpx.AsyncClient(follow_redirects=False)
    await scan_content_discovery(
        TARGET_URL_BASE, DEFAULT_WORDLIST, {}, test_client, mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Content Discovery - Interesting Status 403",
        url=f"{TARGET_URL_BASE}{found_dir}",
        detail="Found accessible resource with status code 403.",
        evidence={"status_code": 403, "wordlist_item": found_dir},
    )


# test_discovery_ignores_404 was already passing, but we'll include it for completeness
@pytest.mark.asyncio
@respx.mock
async def test_discovery_ignores_404(mock_addon):
    """Test: Does not log findings for 404 Not Found responses."""
    respx.route(method="HEAD").respond(404)

    await scan_content_discovery(
        TARGET_URL_BASE,
        DEFAULT_WORDLIST,
        {},
        httpx.AsyncClient(follow_redirects=False),
        mock_addon,
        MagicMock(),
    )

    mock_addon._log_finding.assert_not_called()
