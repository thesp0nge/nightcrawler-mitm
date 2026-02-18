# tests/test_passive_javascript.py
import pytest
import respx
import httpx
import asyncio
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.javascript import check_javascript_libraries, _check_osv_for_vulnerabilities
except ImportError:
    pytest.fail("Could not import check_javascript_libraries", pytrace=False)

# Fixtures mock_addon and sample_url are loaded from conftest.py


def create_mock_response(html_content: str) -> http.Response:
    """Helper function to create a mock mitmproxy response object."""
    return http.Response.make(
        200,
        content=html_content.encode("utf-8"),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )


def test_finds_jquery(mock_addon, sample_url):
    """Test: Correctly identifies a common jQuery version and queues it."""
    html_content = '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

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

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Vulnerable JS Library Found",
        url=sample_url,
        detail="Vulnerable 'jQuery @ 1.12.4' found. OSV ID: GHSA-gxr4-xjj5-5px2. Summary: jQuery before 3.0.0 is vulnerable to XSS",
        evidence={
            "library": "jQuery",
            "version": "1.12.4",
            "vulnerability_id": "GHSA-gxr4-xjj5-5px2",
            "script_url": f"https://code.jquery.com/jquery-{vulnerable_version}.js",
        },
    )

def test_finds_react(mock_addon, sample_url):
    """Test: Correctly identifies a common React version and queues it."""
    html_content = '<script crossorigin src="https://unpkg.com/react-dom@17.0.2/umd/react-dom.production.min.js"></script>'
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once()
    mock_addon.vuln_check_queue.put_nowait.assert_called_once()


def test_finds_multiple_libs(mock_addon, sample_url):
    """Test: Correctly identifies and queues multiple libraries."""
    html_content = """
    <script src="/js/vue@2.6.14.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    """
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    assert mock_addon._log_finding.call_count == 2
    assert mock_addon.vuln_check_queue.put_nowait.call_count == 2


def test_no_known_libs(mock_addon, sample_url):
    """Test: Does not queue anything if no known libraries are present."""
    html_content = '<script src="/js/main-app.1a2b3c.js"></script>'
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_not_called()
    mock_addon.vuln_check_queue.put_nowait.assert_not_called()


def test_not_html_content(mock_addon, sample_url):
    """Test: Does not run on non-HTML content types."""
    response = http.Response.make(
        200, b'{"key":"value"}', {"Content-Type": "application/json"}
    )

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_not_called()
    mock_addon.vuln_check_queue.put_nowait.assert_not_called()

