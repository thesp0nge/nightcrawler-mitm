# Fixtures are loaded from conftest.py


@pytest.mark.asyncio
@respx.mock
async def test_ssti_evaluation(mock_addon, target_info_get):
    """Test: Detects when a template expression is evaluated."""
    payload = "{{7*7}}"
    respx.get("http://test.com/search", params={"query": "test" + payload}).respond(
        200, text="search results for 49"
    )

    await scan_template_injection(
        target_info_get, {}, httpx.AsyncClient(), [payload], mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_called_once()
    _args, kwargs = mock_addon._log_finding.call_args
    assert kwargs["level"] == "ERROR"
    assert "SSTI" in kwargs["finding_type"]


@pytest.mark.asyncio
@respx.mock
async def test_ssti_no_hit_if_reflected(mock_addon, target_info_get):
    """Test: Does NOT log a finding if the payload is simply reflected."""
    payload = "{{7*7}}"
    respx.get("http://test.com/search", params={"query": "test" + payload}).respond(
        200, text="search results for {{7*7}}"
    )

    await scan_template_injection(
        target_info_get, {}, httpx.AsyncClient(), [payload], mock_addon, MagicMock()
    )

    mock_addon._log_finding.assert_not_called()
