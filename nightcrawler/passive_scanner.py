# nightcrawler/passive_scanner.py
# Orchestrates passive scanning by calling checks from the passive_scans sub-package.

from mitmproxy import http, ctx
from typing import TYPE_CHECKING
import logging  # Use standard logging for critical import errors

# --- Import Check Functions ---
# Use try-except for each module to allow partial functionality if one fails
PASSIVE_CHECKS_AVAILABLE: dict[
    str, bool
] = {}  # Dictionary to track available check groups

try:
    from nightcrawler.passive_scans.headers import check_security_headers

    PASSIVE_CHECKS_AVAILABLE["headers"] = True
except ImportError as e:
    logging.error(f"Could not import headers passive scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["headers"] = False

    def check_security_headers(*args, **kwargs):
        pass  # Dummy function


try:
    from nightcrawler.passive_scans.cookies import check_cookie_attributes

    PASSIVE_CHECKS_AVAILABLE["cookies"] = True
except ImportError as e:
    logging.error(f"Could not import cookies passive scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["cookies"] = False

    def check_cookie_attributes(*args, **kwargs):
        pass  # Dummy function


# --- Re-enable import for content checks ---
try:
    from nightcrawler.passive_scans.content import check_info_disclosure

    PASSIVE_CHECKS_AVAILABLE["content"] = True
    logging.debug(
        "Info disclosure checks enabled."
    )  # Use standard logging here before ctx is ready
except ImportError as e:
    logging.error(f"Could not import content passive scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["content"] = False

    def check_info_disclosure(*args, **kwargs):
        pass  # Dummy function


try:
    from nightcrawler.passive_scans.jwt import (
        check_request_for_jwt,
        check_response_for_jwt,
    )

    PASSIVE_CHECKS_AVAILABLE["jwt"] = True
except ImportError as e:
    logging.error(f"Could not import jwt passive scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["jwt"] = False

    def check_request_for_jwt(*args, **kwargs):
        pass  # Dummy function

    def check_response_for_jwt(*args, **kwargs):
        pass  # Dummy function


# Type hint for MainAddon
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Main Orchestration Function ---


def run_all_passive_checks(flow: http.HTTPFlow, addon_instance: "MainAddon"):
    """
    Executes all available passive checks by calling imported functions.
    Requires the addon_instance to call the centralized logging/reporting method.
    """
    # Only proceed if imports were successful for at least some checks
    if not any(PASSIVE_CHECKS_AVAILABLE.values()):
        ctx.log.warn(
            "All passive scan modules failed to import. Passive scanning disabled."
        )
        return

    # ctx.log.debug(f"[Passive Check Orchestrator] Running for {flow.request.pretty_url}") # Verbose

    url = flow.request.pretty_url  # Get URL once

    # --- Checks on Request ---
    if flow.request:
        if PASSIVE_CHECKS_AVAILABLE.get("jwt"):
            try:
                check_request_for_jwt(flow.request, addon_instance)
            except Exception as e:
                # Log errors occurring within specific checks for robustness
                ctx.log.error(f"Error during check_request_for_jwt for {url}: {e}")
        # Add other request checks here...

    # --- Checks on Response ---
    if flow.response:
        # Using try-except around each category of check for resilience
        if PASSIVE_CHECKS_AVAILABLE.get("headers"):
            try:
                check_security_headers(flow.response.headers, url, addon_instance)
            except Exception as e:
                ctx.log.error(f"Error during check_security_headers for {url}: {e}")

        if PASSIVE_CHECKS_AVAILABLE.get("cookies"):
            try:
                check_cookie_attributes(flow.response.cookies, url, addon_instance)
            except Exception as e:
                ctx.log.error(f"Error during check_cookie_attributes for {url}: {e}")

        # --- Re-enable call to content checks ---
        if PASSIVE_CHECKS_AVAILABLE.get("content"):
            try:
                # Pass the full response object as it might be needed for context
                check_info_disclosure(flow.response, url, addon_instance)
            except Exception as e:
                ctx.log.error(f"Error during check_info_disclosure for {url}: {e}")
        # -----------------------------------------

        if PASSIVE_CHECKS_AVAILABLE.get("jwt"):
            try:
                check_response_for_jwt(flow.response, url, addon_instance)
            except Exception as e:
                ctx.log.error(f"Error during check_response_for_jwt for {url}: {e}")

        # Add calls to other response check functions/modules here...


# End of nightcrawler/passive_scanner.py
