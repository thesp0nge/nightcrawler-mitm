# tests/test_passive_content.py
import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.content import ContentScanner
except ImportError:
    pytest.fail("Could not import ContentScanner", pytrace=False)

def create_mock_response(html_content: str) -> http.Response:
    """Helper function to create a mock mitmproxy response object."""
    return http.Response.make(
        200,
        content=html_content.encode("utf-8"),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )

@pytest.mark.asyncio
async def test_finds_google_api_key(mock_addon, sample_url):
    """Test: Correctly identifies a Google API Key."""
    key = "AIza" + "a" * 35
    html_content = f'var apiKey = "{key}";'
    response = create_mock_response(html_content)

    scanner = ContentScanner(mock_addon, MagicMock())
    await scanner.scan_response(response, sample_url)

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Google API Key)",
        url=sample_url,
        detail="Found a potential 'Google API Key' pattern.",
        evidence={"match": key},
    )

@pytest.mark.asyncio
async def test_finds_stripe_api_key(mock_addon, sample_url):
    """Test: Correctly identifies a Stripe API Key."""
    key = "sk_live_" + "123456789012345678901234"
    html_content = f'const key = "{key}";'
    response = create_mock_response(html_content)

    scanner = ContentScanner(mock_addon, MagicMock())
    await scanner.scan_response(response, sample_url)

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Stripe API Key)",
        url=sample_url,
        detail="Found a potential 'Stripe API Key' pattern.",
        evidence={"match": key},
    )
