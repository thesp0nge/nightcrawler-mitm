# tests/test_crawler.py
import pytest
from unittest.mock import MagicMock
from urllib.parse import urlencode

try:
    from nightcrawler.crawler import discover_and_queue_targets
    from nightcrawler.utils import create_target_signature
    from mitmproxy.http import Request  # Import Request for creating mock objects
except ImportError as e:
    pytest.fail(f"Could not import crawler functions or Request: {e}", pytrace=False)

# Fixtures mock_addon and others are loaded from conftest.py


@pytest.fixture
def smart_mock_addon(mocker, mock_addon):
    """Adds queues and sets needed by the crawler to the mock addon."""
    mock_addon.scan_queue = MagicMock()
    mock_addon.scan_queue.put_nowait = MagicMock(name="scan_queue_put")
    mock_addon.crawl_queue = MagicMock()
    mock_addon.crawl_queue.put_nowait = MagicMock(name="crawl_queue_put")
    mock_addon.scanned_targets = set()
    mock_addon.discovered_urls = set()
    mock_addon.logger = MagicMock(spec=["debug", "info", "warn", "error"])
    # The crawler needs the scope to be set on the addon instance
    mock_addon.effective_scope = {"test.com"}
    return mock_addon


def test_crawler_finds_in_scope_links(mocker, smart_mock_addon):
    """Test: The crawler should queue in-scope links and ignore out-of-scope ones."""
    # This test will now use the REAL is_in_scope function, as we've set
    # smart_mock_addon.effective_scope. No need to patch.
    html_content = """
    <a href="/about.html">About Us</a>
    <a href="https://test.com/contact">Contact</a>
    <a href="https://external.com/page">External Site</a>
    """
    discover_and_queue_targets(html_content, "http://test.com/", smart_mock_addon)

    # Assert that the crawl queue was called exactly twice for the in-scope links
    assert smart_mock_addon.crawl_queue.put_nowait.call_count == 2
    smart_mock_addon.crawl_queue.put_nowait.assert_any_call(
        "http://test.com/about.html"
    )
    # --- CORRECTED ASSERTION: The test now expects the correct 'https' scheme ---
    smart_mock_addon.crawl_queue.put_nowait.assert_any_call("https://test.com/contact")


def test_crawler_finds_post_form_for_scanning(smart_mock_addon):
    """Test: The crawler should find a POST form and queue it for active scanning."""
    html_content = '<form action="/login" method="POST"><input name="user"><input name="pass"></form>'
    discover_and_queue_targets(html_content, "http://test.com/", smart_mock_addon)

    smart_mock_addon.scan_queue.put_nowait.assert_called_once()
    call_args, _ = smart_mock_addon.scan_queue.put_nowait.call_args
    scan_details = call_args[0]

    assert scan_details["method"] == "POST"
    assert scan_details["url"] == "http://test.com/login"
    assert "user" in scan_details["data"]
    assert "pass" in scan_details["data"]
    smart_mock_addon.crawl_queue.put_nowait.assert_not_called()


def test_crawler_finds_get_form_for_scanning(smart_mock_addon):
    """Test: The crawler should find a GET form and queue it for active scanning."""
    html_content = '<form action="/search" method="GET"><input name="q"></form>'
    discover_and_queue_targets(html_content, "http://test.com/", smart_mock_addon)

    smart_mock_addon.scan_queue.put_nowait.assert_called_once()
    call_args, _ = smart_mock_addon.scan_queue.put_nowait.call_args
    scan_details = call_args[0]

    assert scan_details["method"] == "GET"
    assert scan_details["url"] == "http://test.com/search"
    assert "q" in scan_details["params"]
    assert not scan_details["data"]


def test_crawler_avoids_duplicate_form_scans(smart_mock_addon):
    """Test: The crawler should not queue a form for scanning if it's already been seen."""
    html_content = '<form action="/login" method="POST"><input name="user"></form>'

    # Create a mock request to generate a signature
    mock_req = Request.make("POST", "http://test.com/login", content=b"user=test")
    mock_req.urlencoded_form = {"user": "test"}

    # --- CORRECTED CALL: Pass a mock logger to the signature function ---
    signature = create_target_signature(mock_req, logger=MagicMock())
    smart_mock_addon.scanned_targets.add(signature)

    # Run discovery
    discover_and_queue_targets(html_content, "http://test.com/", smart_mock_addon)

    # Assert that nothing was queued for scanning
    smart_mock_addon.scan_queue.put_nowait.assert_not_called()
