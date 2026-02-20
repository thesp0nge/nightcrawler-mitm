# tests/conftest.py
# This file provides shared fixtures for all test modules.

import pytest
import asyncio
from unittest.mock import MagicMock

try:
    from nightcrawler.addon import MainAddon
    from nightcrawler.config import CONFIDENCE_LOW
except ImportError:
    # Define a dummy class if addon cannot be imported.
    # This allows test collection to succeed even if there are import issues in the main code.
    class MainAddon:
        pass
    CONFIDENCE_LOW = 0


# --- Mocking Fixture ---
@pytest.fixture
def mock_addon(mocker):
    """
    Provides a mock instance of the MainAddon, reset for each test.
    This is now available to all test files automatically.
    """
    # Use spec=MainAddon to ensure the mock has the same attributes/methods
    # as the real class, which helps catch typos.
    instance = mocker.MagicMock(spec=MainAddon)

    # Define the methods we expect to call from our scanners
    instance._log_finding = MagicMock(name="_log_finding")
    instance.register_injection = MagicMock(name="register_injection")
    instance.vuln_check_queue = MagicMock(spec=asyncio.Queue)

    # Mock any attributes that the scanners might need
    instance.user_agent = "Nightcrawler-Test-UA/1.0"
    instance.xss_stored_format = ""  # Provide a default for tests
    instance.xss_stored_prefix = "ncXSS"
    instance.smart_targeting = False
    instance.min_confidence = CONFIDENCE_LOW

    return instance


# --- Shared Test Data Fixtures ---
@pytest.fixture
def sample_url() -> str:
    """Provides a sample HTTPS URL for testing passive scanners."""
    return "https://example.com/test"


@pytest.fixture
def target_info_get() -> dict:
    """Provides a sample target_info dictionary for a GET request."""
    return {
        "url": "http://test.com/search?query=test",
        "method": "GET",
        "params": {"query": "test"},
        "data": {},
        "headers": {"User-Agent": "Test Browser"},
        "cookies": {},
    }


@pytest.fixture
def target_info_post() -> dict:
    """Provides a sample target_info dictionary for a POST request."""
    return {
        "url": "http://test.com/comment",
        "method": "POST",
        "params": {},
        "data": {"comment": "safe comment"},
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Test Browser",
        },
        "cookies": {},
    }
