# tests/test_xss_scanner.py
import pytest
import httpx
import html
import respx
import re
from unittest.mock import MagicMock

try:
    from nightcrawler.active_scans.xss_scanner import XSSScanner
except ImportError as e:
    pytest.fail(f"Could not import XSSScanner: {e}", pytrace=False)

pytestmark = pytest.mark.asyncio

# --- Test Data ---
TARGET_URL_GET = "http://test.com/search"
TARGET_PARAM_GET = "query"
REFLECTED_PAYLOADS = ["<script>alert('XSSR1')</script>"]
STORED_PREFIX = "testNC"
STORED_FORMAT = "[[probe_id:{probe_id}]]"

@pytest.mark.asyncio
@respx.mock
async def test_reflected_exact_hit(mock_addon, target_info_get):
    """Test: Exact payload is reflected, should log ERROR."""
    payload_hit = REFLECTED_PAYLOADS[0]
    mock_addon.xss_reflected_payloads = [payload_hit]
    mock_addon.xss_stored_format = STORED_FORMAT
    mock_addon.xss_stored_prefix = STORED_PREFIX
    
    target_info_get["url"] = TARGET_URL_GET
    target_info_get["params"] = {TARGET_PARAM_GET: "test"}

    def xss_side_effect(request):
        url_str = str(request.url).lower()
        if "alert" in url_str:
            return httpx.Response(200, text=f"<html>{payload_hit}</html>", headers={"Content-Type": "text/html"})
        if "ncv" in url_str:
            return httpx.Response(200, text="<html><ncv1234></ncv1234></html>", headers={"Content-Type": "text/html"})
        return httpx.Response(200, text="<html>clean</html>", headers={"Content-Type": "text/html"})

    respx.route(url=re.compile(r".*")).side_effect = xss_side_effect

    scanner = XSSScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient(follow_redirects=False))

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # XSSScanner uses positional arguments
    assert args[0] == "ERROR"
    assert "XSS Found" in args[1]

@pytest.mark.asyncio
@respx.mock
async def test_stored_inject_registers_payload(mock_addon, target_info_post):
    """Test: Stored XSS injection attempt registers the correct probe details."""
    mock_addon.xss_reflected_payloads = []
    mock_addon.xss_stored_prefix = STORED_PREFIX
    mock_addon.xss_stored_format = STORED_FORMAT

    respx.post(url=re.compile(r".*")).respond(200, text="Comment submitted")

    scanner = XSSScanner(mock_addon, MagicMock())
    await scanner.run(target_info_post, {}, httpx.AsyncClient(follow_redirects=False))

    mock_addon.register_injection.assert_called_once()
