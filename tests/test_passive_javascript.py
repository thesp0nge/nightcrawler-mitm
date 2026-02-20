# tests/test_passive_javascript.py
import pytest
import respx
import httpx
import asyncio
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.javascript import JavaScriptScanner, _check_osv_for_vulnerabilities
except ImportError:
    pytest.fail("Could not import JavaScriptScanner", pytrace=False)

def create_mock_response(html_content: str) -> http.Response:
    """Helper function to create a mock mitmproxy response object."""
    return http.Response.make(
        200,
        content=html_content.encode("utf-8"),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )

@pytest.mark.asyncio
async def test_finds_jquery(mock_addon, sample_url):
    """Test: Correctly identifies a common jQuery version and queues it."""
    html_content = '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
    response = create_mock_response(html_content)

    scanner = JavaScriptScanner(mock_addon, MagicMock())
    await scanner.scan_response(response, sample_url)

    mock_addon._log_finding.assert_called_once()
    mock_addon.vuln_check_queue.put_nowait.assert_called_once()

@pytest.mark.asyncio
@respx.mock
async def test_vulnerable_jquery_found(mock_addon, sample_url):
    """Test: Direct call to OSV checker logs a vulnerability."""
    vulnerable_version = "1.12.4"
    osv_payload = {"vulns": [{"id": "GHSA-gxr4-xjj5-5px2", "summary": "jQuery before 3.0.0 is vulnerable to XSS"}]}
    respx.post("https://api.osv.dev/v1/query").respond(200, json=osv_payload)

    lib_details = {
        "library": "jQuery",
        "version": vulnerable_version,
        "url": sample_url,
        "script_url": f"https://code.jquery.com/jquery-{vulnerable_version}.js",
    }
    
    http_client = httpx.AsyncClient()
    logger = MagicMock()

    await _check_osv_for_vulnerabilities(lib_details, http_client, mock_addon, logger)

    mock_addon._log_finding.assert_called_once()

@pytest.mark.asyncio
async def test_finds_multiple_libs(mock_addon, sample_url):
    """Test: Correctly identifies and queues multiple libraries."""
    html_content = """
    <script src="/js/vue@2.6.14.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    """
    response = create_mock_response(html_content)

    scanner = JavaScriptScanner(mock_addon, MagicMock())
    await scanner.scan_response(response, sample_url)

    assert mock_addon._log_finding.call_count == 2
    assert mock_addon.vuln_check_queue.put_nowait.call_count == 2
