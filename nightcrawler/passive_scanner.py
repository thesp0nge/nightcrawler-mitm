# nightcrawler/passive_scanner.py
# Contains logic for performing passive checks on HTTP responses.

from mitmproxy import http, ctx

# Import the correct type for flow.response.cookies
from mitmproxy.coretypes.multidict import MultiDictView
from typing import Dict, Optional, List  # Keep Dict for headers type hint


# Main function called by the addon's response hook
def run_all_passive_checks(flow: http.HTTPFlow):
    """Executes all defined passive checks on the intercepted response."""
    # ctx.log.debug(f"[Passive Check] Running for {flow.request.pretty_url}") # Uncomment for verbose logging
    # Call individual check functions
    _check_security_headers(flow.response.headers, flow.request.pretty_url)
    # Pass the actual cookies object from the flow
    _check_cookie_attributes(flow.response.cookies, flow.request.pretty_url)
    _check_info_disclosure(flow.response.text, flow.request.pretty_url)
    # Add calls to other passive check functions here...


# "Private" functions for individual checks (prefix with _)
def _check_security_headers(headers: Dict[str, str], url: str):
    """Checks for the presence of common security headers."""
    missing = []
    if not headers.get("Strict-Transport-Security"):
        missing.append("Strict-Transport-Security")
    if not headers.get("Content-Security-Policy") and not headers.get(
        "Content-Security-Policy-Report-Only"
    ):
        missing.append("Content-Security-Policy")
    if not headers.get("X-Content-Type-Options"):
        missing.append("X-Content-Type-Options")
    if not headers.get("X-Frame-Options"):
        missing.append("X-Frame-Options")
    if not headers.get("Referrer-Policy"):
        missing.append("Referrer-Policy")
    if missing:
        ctx.log.warn(f"[Passive Scan] Missing Headers: {', '.join(missing)} at {url}")


def _check_cookie_attributes(cookies: MultiDictView, url: str):
    """
    Checks Secure, HttpOnly, and SameSite attributes for Set-Cookie headers.
    'cookies' argument is expected to be flow.response.cookies (a MultiDictView).
    """
    # Note: This function actually iterates over raw Set-Cookie headers
    # obtained via get_all(), not the parsed key-value pairs in the view.
    set_cookie_headers = cookies.get_all("Set-Cookie")
    if not set_cookie_headers:
        return  # No Set-Cookie headers found

    for header_value in set_cookie_headers:
        issues = []
        header_lower = header_value.lower()
        cookie_name = header_value.split("=", 1)[0].strip()
        if not cookie_name:
            continue

        if "; secure" not in header_lower:
            if url.startswith("https://"):
                issues.append("Missing Secure flag")
        if "; httponly" not in header_lower:
            issues.append("Missing HttpOnly flag")
        if "samesite=" not in header_lower:
            issues.append("Missing SameSite attribute")
        elif "samesite=none" in header_lower and "; secure" not in header_lower:
            issues.append("SameSite=None requires Secure flag")

        if issues:
            ctx.log.warn(
                f"[Passive Scan] Cookie {cookie_name!r} issues: {', '.join(issues)} at {url}"
            )


def _check_info_disclosure(response_text: Optional[str], url: str):
    """Checks for comments or potential keywords in the response body."""
    if not response_text:
        return

    # Example: Find HTML/JS comments (requires import re)
    # Needs refinement to avoid excessive logging or false positives
    # import re
    # comments = re.findall(r"|/\*.*?\*/|//.*", response_text, re.DOTALL)
    # if comments:
    #     ctx.log.info(f"[Passive Scan] Found HTML/JS comments at {url}")

    # Example: Search for potential keywords (HIGH RISK OF FALSE POSITIVES)
    # Requires much more refined regex or specific logic based on context.
    # import re
    # potential_keywords = ['error', 'debug', 'trace', 'password', 'secret', 'apikey', 'aws_access_key']
    # for keyword in potential_keywords:
    #      # Use word boundaries (\b) to avoid matching parts of words
    #      if re.search(r'\b' + re.escape(keyword) + r'\b', response_text, re.IGNORECASE):
    #           ctx.log.warn(f"[Passive Scan] Potential keyword '{keyword}' found in response body at {url}")
    pass  # Placeholder - Implement more robust checks here if desired
