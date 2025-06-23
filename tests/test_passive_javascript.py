# tests/test_passive_javascript.py
import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.javascript import check_javascript_libraries
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
    """Test: Correctly identifies a common jQuery version."""
    html_content = '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
    response = create_mock_response(html_content)

    # Pass a MagicMock as the logger
    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="INFO",
        finding_type="Passive Scan - JS Library Found",
        url=sample_url,
        detail="Identified Library: jQuery version 3.6.0",
        evidence={
            "script_url": "https://code.jquery.com/jquery-3.6.0.min.js",
            "library": "jQuery",
            "version": "3.6.0",
        },
    )


def test_finds_react(mock_addon, sample_url):
    """Test: Correctly identifies a common React version."""
    html_content = '<script crossorigin src="https://unpkg.com/react-dom@17.0.2/umd/react-dom.production.min.js"></script>'
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="INFO",
        finding_type="Passive Scan - JS Library Found",
        url=sample_url,
        detail="Identified Library: React version 17.0.2",
        evidence={
            "script_url": "https://unpkg.com/react-dom@17.0.2/umd/react-dom.production.min.js",
            "library": "React",
            "version": "17.0.2",
        },
    )


def test_finds_multiple_libs(mock_addon, sample_url):
    """Test: Correctly identifies multiple libraries on the same page."""
    html_content = """
    <script src="/js/vue@2.6.14.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    """
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    assert mock_addon._log_finding.call_count == 2
    mock_addon._log_finding.assert_any_call(
        level="INFO",
        finding_type="Passive Scan - JS Library Found",
        url=sample_url,
        detail="Identified Library: Vue.js version 2.6.14",
        evidence={
            "script_url": "/js/vue@2.6.14.js",
            "library": "Vue.js",
            "version": "2.6.14",
        },
    )
    mock_addon._log_finding.assert_any_call(
        level="INFO",
        finding_type="Passive Scan - JS Library Found",
        url=sample_url,
        detail="Identified Library: Bootstrap version 4.5.2",
        evidence={
            "script_url": "https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js",
            "library": "Bootstrap",
            "version": "4.5.2",
        },
    )


def test_no_known_libs(mock_addon, sample_url):
    """Test: Does not log findings if no known libraries are present."""
    html_content = '<script src="/js/main-app.1a2b3c.js"></script>'
    response = create_mock_response(html_content)

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_not_called()


def test_not_html_content(mock_addon, sample_url):
    """Test: Does not run on non-HTML content types."""
    response = http.Response.make(
        200, b'{"key":"value"}', {"Content-Type": "application/json"}
    )

    check_javascript_libraries(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_not_called()
