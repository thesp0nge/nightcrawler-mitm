# nightcrawler/passive_scans/cookies.py
# Passive checks related to Set-Cookie headers and attributes.

from mitmproxy import http
from mitmproxy.coretypes.multidict import MultiDictView
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


def check_cookie_attributes(
    response: http.Response, url: str, addon_instance: "MainAddon", logger: Any
):
    """
    Checks Secure, HttpOnly, and SameSite attributes for Set-Cookie headers.
    Logs findings using the provided addon_instance.
    """
    cookies = response.cookies
    set_cookie_headers = cookies.get_all("Set-Cookie")
    if not set_cookie_headers:
        return

    for header_value in set_cookie_headers:
        issues = []
        header_lower = header_value.lower()
        cookie_name_part = header_value.split("=", 1)[0].strip()
        if not cookie_name_part or ";" in cookie_name_part:
            logger.debug(
                f"Skipping potentially malformed Set-Cookie header at {url}: {header_value[:50]}..."
            )
            continue
        cookie_name = cookie_name_part

        is_https = url.startswith("https://")

        if "; secure" not in header_lower:
            if is_https:
                issues.append("Missing Secure flag")
        if "; httponly" not in header_lower:
            issues.append("Missing HttpOnly flag")
        if "samesite=" not in header_lower:
            issues.append("Missing SameSite attribute")
        elif "samesite=none" in header_lower and "; secure" not in header_lower:
            issues.append("SameSite=None requires Secure flag")

        if issues:
            addon_instance._log_finding(
                level="WARN",
                finding_type="Passive Scan - Cookie Attribute(s)",
                url=url,
                detail=f"Cookie '{cookie_name}' issues: {', '.join(issues)}",
                evidence={"header": header_value},
            )
