import pytest
import httpx
import respx
import re
from unittest.mock import MagicMock
from nightcrawler.active_scans.template_injection import TemplateInjectionScanner

# Fixtures are loaded from conftest.py

@pytest.mark.asyncio
@respx.mock
async def test_ssti_evaluation(mock_addon, target_info_get):
    """Test: Detects when a template expression is evaluated."""
    payload = "{{7*7}}"
    mock_addon.ssti_payloads = [payload]
    target_info_get["url"] = "http://test.com/search"
    target_info_get["params"] = {"query": "test"}
    
    # Just mock ANY request to return the success pattern
    respx.get(url=re.compile(r".*")).respond(200, text="search results for 1787569")

    scanner = TemplateInjectionScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    assert mock_addon._log_finding.called
    args, kwargs = mock_addon._log_finding.call_args
    # TemplateInjectionScanner uses keyword arguments
    assert kwargs["level"] == "ERROR"
    assert "SSTI" in kwargs["finding_type"]

@pytest.mark.asyncio
@respx.mock
async def test_ssti_no_hit_if_reflected(mock_addon, target_info_get):
    """Test: Does NOT log a finding if the payload is simply reflected."""
    payload = "{{7*7}}"
    mock_addon.ssti_payloads = [payload]
    respx.get(url=re.compile(r".*")).respond(200, text="search results for {{7*7}}")

    scanner = TemplateInjectionScanner(mock_addon, MagicMock())
    await scanner.run(target_info_get, {}, httpx.AsyncClient())

    mock_addon._log_finding.assert_not_called()
