# nightcrawler/passive_scanner.py
# Orchestrates passive scanning by calling checks from the passive_scans sub-package.

from mitmproxy import http, ctx
from typing import TYPE_CHECKING, Any
import logging

# --- Import Check Functions ---
# Use try-except to handle potential import errors gracefully
PASSIVE_CHECKS_AVAILABLE: dict[str, bool] = {}
try:
    from nightcrawler.passive_scans.headers import check_security_headers

    PASSIVE_CHECKS_AVAILABLE["headers"] = True
except ImportError as e:
    logging.error(f"Could not import headers scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["headers"] = False
try:
    from nightcrawler.passive_scans.cookies import check_cookie_attributes

    PASSIVE_CHECKS_AVAILABLE["cookies"] = True
except ImportError as e:
    logging.error(f"Could not import cookies scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["cookies"] = False
try:
    from nightcrawler.passive_scans.content import check_info_disclosure

    PASSIVE_CHECKS_AVAILABLE["content"] = True
except ImportError as e:
    logging.error(f"Could not import content scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["content"] = False
try:
    from nightcrawler.passive_scans.jwt import (
        check_request_for_jwt,
        check_response_for_jwt,
    )

    PASSIVE_CHECKS_AVAILABLE["jwt"] = True
except ImportError as e:
    logging.error(f"Could not import jwt scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["jwt"] = False
try:
    from nightcrawler.passive_scans.javascript import check_javascript_libraries

    PASSIVE_CHECKS_AVAILABLE["javascript"] = True
except ImportError as e:
    logging.error(f"Could not import javascript scan module: {e}")
    PASSIVE_CHECKS_AVAILABLE["javascript"] = False

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Main Orchestration Function ---
def run_all_passive_checks(
    flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any
):
    """Executes all available passive checks by calling imported functions."""
    if not any(PASSIVE_CHECKS_AVAILABLE.values()):
        return

    addon_instance.stats["passive_total"] += 1
    url = flow.request.pretty_url
    logger.debug(f"[Passive Orchestrator] Running ALL checks for {url}")

    # Checks on Request
    if flow.request and PASSIVE_CHECKS_AVAILABLE.get("jwt"):
        try:
            logger.debug("[Passive Orchestrator] -> Calling check_request_for_jwt...")
            check_request_for_jwt(flow.request, addon_instance, logger)
        except Exception as e:
            logger.error(f"Error during JWT request check for {url}: {e}")

    # Checks on Response
    if flow.response:
        # Each check is wrapped in a try-except for resilience.
        if PASSIVE_CHECKS_AVAILABLE.get("headers"):
            try:
                logger.debug(
                    "[Passive Orchestrator] -> Calling check_security_headers..."
                )
                check_security_headers(flow.response, url, addon_instance, logger)
            except Exception as e:
                logger.error(f"Error during header check for {url}: {e}")

        if PASSIVE_CHECKS_AVAILABLE.get("cookies"):
            try:
                logger.debug(
                    "[Passive Orchestrator] -> Calling check_cookie_attributes..."
                )
                check_cookie_attributes(flow.response, url, addon_instance, logger)
            except Exception as e:
                logger.error(f"Error during cookie check for {url}: {e}")

        if PASSIVE_CHECKS_AVAILABLE.get("content"):
            try:
                logger.debug(
                    "[Passive Orchestrator] -> Calling check_info_disclosure..."
                )
                check_info_disclosure(flow.response, url, addon_instance, logger)
            except Exception as e:
                logger.error(f"Error during info disclosure check for {url}: {e}")

        if PASSIVE_CHECKS_AVAILABLE.get("jwt"):
            try:
                logger.debug(
                    "[Passive Orchestrator] -> Calling check_response_for_jwt..."
                )
                check_response_for_jwt(flow.response, url, addon_instance, logger)
            except Exception as e:
                logger.error(f"Error during JWT response check for {url}: {e}")

        if PASSIVE_CHECKS_AVAILABLE.get("javascript"):
            try:
                logger.debug(
                    "[Passive Orchestrator] -> Calling check_javascript_libraries..."
                )
                check_javascript_libraries(flow.response, url, addon_instance, logger)
            except Exception as e:
                logger.error(f"Error during JS library check for {url}: {e}")

    logger.debug(f"[Passive Orchestrator] Finished all checks for {url}")
