# nightcrawler/passive_scans/websockets.py
# Passive checks related to WebSocket connection security.

from mitmproxy import http
from typing import TYPE_CHECKING, Any
from nightcrawler.passive_scans.base import PassiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

COMMON_SESSION_COOKIE_NAMES = {"sessionid", "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid", "sid", "session", "_session_id"}

class WebSocketScanner(PassiveScanner):
    name: str = "WebSocket"

    async def scan_request(self, request: http.Request):
        """Checks WebSocket upgrade request for authentication."""
        # Note: In mitmproxy, WebSocket upgrade is an HTTP request.
        # We check for upgrade header to confirm it's a websocket attempt
        if request.headers.get("Upgrade", "").lower() != "websocket":
            return

        url = request.pretty_url
        cookie_header = request.headers.get("Cookie", None)

        if not cookie_header:
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - WebSocket Without Cookie", url=url,
                detail="WebSocket connection was established without any Cookie header.",
                evidence={"host": request.host},
            )
            return

        found_session_cookie = any(f"{name}=" in cookie_header.lower() for name in COMMON_SESSION_COOKIE_NAMES)

        if not found_session_cookie:
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - WebSocket No Session Cookie", url=url,
                detail="No common session identifier (e.g., 'sessionid') found in WebSocket upgrade.",
                evidence={"cookie_header": cookie_header},
            )
