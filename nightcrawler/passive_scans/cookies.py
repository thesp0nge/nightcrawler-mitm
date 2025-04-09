# nightcrawler/passive_scans/cookies.py
# Passive checks related to Set-Cookie headers and attributes.

from mitmproxy import ctx, http
from mitmproxy.coretypes.multidict import MultiDictView
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon


def check_cookie_attributes(
    cookies: MultiDictView, url: str, addon_instance: "MainAddon"
):
    """
    Checks Secure, HttpOnly, and SameSite attributes for Set-Cookie headers.
    Logs findings using the provided addon_instance.

    Args:
        cookies: The flow.response.cookies object (a MultiDictView).
        url: The URL of the response.
        addon_instance: The instance of the main addon for logging.
    """
    set_cookie_headers = cookies.get_all("Set-Cookie")  # Get raw header values
    if not set_cookie_headers:
        return  # No Set-Cookie headers found in this response

    for header_value in set_cookie_headers:
        issues = []
        header_lower = header_value.lower()  # For case-insensitive checks

        # Basic parsing for the cookie name (part before the first '=')
        cookie_name_part = header_value.split("=", 1)[0].strip()
        # Basic validation: skip if name is empty or seems malformed (contains ';')
        if not cookie_name_part or ";" in cookie_name_part:
            ctx.log.debug(
                f"Skipping potentially malformed Set-Cookie header at {url}: {header_value[:50]}..."
            )
            continue
        cookie_name = cookie_name_part

        is_https = url.startswith("https://")

        # Check for Secure flag (should be present on HTTPS sites)
        if "; secure" not in header_lower:
            if is_https:
                issues.append("Missing Secure flag")

        # Check for HttpOnly flag
        if "; httponly" not in header_lower:
            issues.append("Missing HttpOnly flag")

        # Check SameSite attribute
        if "samesite=" not in header_lower:
            # Browsers might apply defaults (often Lax), but explicit declaration is best practice.
            issues.append("Missing SameSite attribute")
        elif "samesite=none" in header_lower:
            # SameSite=None MUST be accompanied by Secure flag.
            if "; secure" not in header_lower:
                issues.append("SameSite=None requires Secure flag")
        # Could add warnings for Lax vs Strict depending on context if needed.

        if issues:
            # Use repr() for the name in case it contains unusual characters.
            # Log the finding using the centralized method.
            addon_instance._log_finding(
                level="WARN",
                finding_type="Passive Scan - Cookie Attribute(s)",
                url=url,
                detail=f"Cookie '{cookie_name}' issues: {', '.join(issues)}",
                evidence={
                    "header": header_value
                },  # Provide the full header as evidence
            )
