# tests/test_addon_commands.py
# Unit tests for interactive commands defined in the MainAddon.

import pytest
from unittest.mock import MagicMock, call, mock_open  # <-- Import mock_open
import pathlib

# Import the class to test
try:
    from nightcrawler.addon import MainAddon
except ImportError:
    pytest.fail("Could not import MainAddon", pytrace=False)

# Fixtures are loaded from conftest.py


def test_dump_urls_writes_file(mocker):
    """
    Test: The dump_urls command correctly writes discovered URLs to a file.
    """
    # 1. Setup: Create a REAL instance of the addon
    addon = MainAddon()
    # Set the necessary state on the real instance
    addon.discovered_urls = {
        "http://test.com/page2",
        "http://test.com/page1",
        "http://test.com/about",
    }
    # Setattr is used to add an attribute to the real instance for testing
    setattr(addon, "effective_scope", {"test.com"})

    # Mock the global ctx object that the command uses for logging alerts
    mock_ctx = mocker.patch("nightcrawler.addon.ctx")

    # --- CORRECTED MOCKING STRATEGY FOR FILE I/O ---
    # Use mocker.mock_open() to correctly simulate the file handle
    m = mock_open()
    mocker.patch("builtins.open", m)
    # -----------------------------------------------

    # 2. Call the REAL method under test
    addon.dump_urls()

    # 3. Assertions
    # Check that open() was called with the correct file path and mode
    m.assert_called_once_with(
        pathlib.Path("nightcrawler_links.txt").resolve(), "w", encoding="utf-8"
    )

    # Get the mock representing the file handle
    file_handle = m()

    # Check that the write() method was called with the correct content.
    # The URLs should be sorted alphabetically.
    file_handle.write.assert_any_call("http://test.com/about\n")
    file_handle.write.assert_any_call("http://test.com/page1\n")
    file_handle.write.assert_any_call("http://test.com/page2\n")

    # Check that the confirmation alert was logged
    mock_ctx.log.alert.assert_called_once()
    alert_message = mock_ctx.log.alert.call_args[0][0]
    assert "Successfully dumped 3 URLs" in alert_message


def test_dump_urls_no_urls(mocker, capsys):
    """
    Test: The dump_urls command does nothing and alerts the user
    if no URLs have been discovered.
    """
    # 1. Setup: Create a REAL instance and ensure state is empty
    addon = MainAddon()
    addon.discovered_urls = set()

    # Mock dependencies
    mock_open = mocker.patch("builtins.open")

    # 2. Call the REAL method
    addon.dump_urls()

    # 3. Assertions
    # File should not have been opened
    mock_open.assert_not_called()
    # A warning should have been logged to stderr
    captured = capsys.readouterr()
    assert "[Nightcrawler] No URLs discovered yet to dump." in captured.err
