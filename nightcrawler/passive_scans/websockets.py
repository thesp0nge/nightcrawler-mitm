# nightcrawler/passive_scans/websockets.py
# Passive checks related to WebSocket connection security.

import re
from mitmproxy import http
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# A set of common names for session cookies.
# This list can be expanded.
COMMON_SESSION_COOKIE_NAMES = {
    "sessionid",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "connect.sid",
    "sid",
    "session",
    "_session_id",
}


def check_websocket_authentication(
    flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any
):
    """
    Checks the initial HTTP upgrade request for a WebSocket connection
    to see if it contains a common session cookie.

    Args:
        flow: The mitmproxy HTTPFlow object for the connection.
        addon_instance: The instance of the main addon for logging findings.
        logger: The logger instance for debug messages.
    """
    url = flow.request.pretty_url
    logger.debug(f"[WS Auth Check] Analyzing WebSocket upgrade request for {url}")

    cookie_header = flow.request.headers.get("Cookie", None)

    # Case 1: No Cookie header at all. This is highly suspicious.
    if not cookie_header:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - WebSocket Without Cookie",
            url=url,
            detail="WebSocket connection was established without any Cookie header. The endpoint may be unauthenticated.",
            evidence={"host": flow.request.host},
        )
        return

    # Case 2: Cookie header exists, but does it contain a session ID?
    # We check by looking for "key=" patterns for our common names.
    found_session_cookie = False
    for session_name in COMMON_SESSION_COOKIE_NAMES:
        # Use a simple but effective check to see if "sessionid=" (for example) is in the header.
        # A regex could be more precise but this is generally sufficient.
        if f"{session_name}=" in cookie_header.lower():
            found_session_cookie = True
            break  # Found one, no need to check others

    if not found_session_cookie:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - WebSocket No Session Cookie",
            url=url,
            detail="Cookie header was present on WebSocket upgrade, but no common session identifier (e.g., 'sessionid') was found.",
            evidence={"cookie_header": cookie_header},
        )
    else:
        logger.debug(
            f"[WS Auth Check] Found potential session cookie in upgrade request for {url}."
        )
