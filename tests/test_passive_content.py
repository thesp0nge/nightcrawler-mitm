# tests/test_passive_content.py
import pytest
from mitmproxy import http
from unittest.mock import MagicMock

try:
    from nightcrawler.passive_scans.content import check_info_disclosure
except ImportError:
    pytest.fail("Could not import check_info_disclosure", pytrace=False)

# Fixtures mock_addon and sample_url are loaded from conftest.py

def create_mock_response(html_content: str) -> http.Response:
    """Helper function to create a mock mitmproxy response object."""
    return http.Response.make(
        200,
        content=html_content.encode("utf-8"),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )

def test_finds_google_api_key(mock_addon, sample_url):
    """Test: Correctly identifies a Google API Key."""
    key = "AIza" + "a" * 35
    html_content = f'var apiKey = "{key}";'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Google API Key)",
        url=sample_url,
        detail="Found a potential 'Google API Key' pattern.",
        evidence={"match": key},
    )

def test_finds_stripe_api_key(mock_addon, sample_url):
    """Test: Correctly identifies a Stripe API Key."""
    key = "sk_live_" + "123456789012345678901234"
    html_content = f'const key = "{key}";'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Stripe API Key)",
        url=sample_url,
        detail="Found a potential 'Stripe API Key' pattern.",
        evidence={"match": key},
    )

def test_finds_slack_token(mock_addon, sample_url):
    """Test: Correctly identifies a Slack Token."""
    token_parts = ["xoxb", "123456789012", "123456789012", "123456789012", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"]
    token = "-".join(token_parts)
    html_content = token
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Slack Token)",
        url=sample_url,
        detail="Found a potential 'Slack Token' pattern.",
        evidence={"match": token},
    )

def test_finds_generic_api_key(mock_addon, sample_url):
    """Test: Correctly identifies a generic API Key pattern."""
    key_string = "ApiKey: 1234567890abcdef1234567890abcdef"
    html_content = key_string
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Generic API Key)",
        url=sample_url,
        detail="Found a potential 'Generic API Key' pattern.",
        evidence={"match": key_string},
    )

def test_finds_credit_card(mock_addon, sample_url):
    """Test: Correctly identifies a credit card number."""
    html_content = '4111111111111111'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Credit Card Number)",
        url=sample_url,
        detail="Found a potential 'Credit Card Number' pattern.",
        evidence={"match": "4111111111111111"},
    )

def test_finds_ssn(mock_addon, sample_url):
    """Test: Correctly identifies a Social Security Number."""
    html_content = '<td>123-45-6789</td>'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Social Security Number)",
        url=sample_url,
        detail="Found a potential 'Social Security Number' pattern.",
        evidence={"match": "123-45-6789"},
    )

def test_finds_aws_key(mock_addon, sample_url):
    """Test: Correctly identifies an AWS Key ID."""
    html_content = 'AKIAIOSFODNN7EXAMPLE'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="WARN",
        finding_type="Passive Scan - Info Disclosure (Potential AWS Key ID)",
        url=sample_url,
        detail="Found a potential 'Potential AWS Key ID' pattern.",
        evidence={"match": "AKIAIOSFODNN7EXAMPLE"},
    )

def test_finds_private_key(mock_addon, sample_url):
    """Test: Correctly identifies a private key header."""
    html_content = '-----BEGIN RSA PRIVATE KEY-----'
    response = create_mock_response(html_content)

    check_info_disclosure(response, sample_url, mock_addon, MagicMock())

    mock_addon._log_finding.assert_called_once_with(
        level="ERROR",
        finding_type="Passive Scan - Info Disclosure (Potential Private Key)",
        url=sample_url,
        detail="Found a potential 'Potential Private Key' pattern.",
        evidence={"match": "-----BEGIN RSA PRIVATE KEY-----"},
    )

