# nightcrawler/passive_scans/headers.py
# Passive checks related to HTTP security headers.

import re  # Needed for basic CSP check example
from mitmproxy import ctx, http
from typing import Dict, TYPE_CHECKING

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Headers to check for presence (consider making this configurable)
EXPECTED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]
CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only"
MIN_HSTS_AGE = 15552000  # Approx 6 months in seconds


def check_security_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """
    Checks for presence and basic validity of common security headers.
    Logs findings using the provided addon_instance.
    """
    missing = []
    present = {}  # Store values of present headers for potential further checks

    # Check for expected headers using case-insensitive get()
    for header_name in EXPECTED_SECURITY_HEADERS:
        value = headers.get(header_name)
        if value is not None:  # Header exists
            present[header_name] = value
        elif header_name == "Content-Security-Policy":
            # Report CSP missing only if Report-Only is also missing
            if not headers.get(CSP_REPORT_ONLY_HEADER):
                missing.append(header_name)
        # Exclude CSP check here if already handled above
        elif header_name != "Content-Security-Policy":
            missing.append(header_name)

    # --- Report Missing Headers ---
    if missing:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Missing Header(s)",
            url=url,
            detail=f"Missing Recommended Security Headers: {', '.join(missing)}",
            evidence={"missing": missing},
        )

    # --- Basic Checks for Present Headers ---

    # HSTS Check (if present)
    hsts_value = present.get("Strict-Transport-Security")
    if hsts_value:
        if "max-age" in hsts_value.lower():
            try:
                max_age_str = (
                    hsts_value.lower().split("max-age=")[1].split(";")[0].strip()
                )
                max_age = int(max_age_str)
                if max_age < MIN_HSTS_AGE:
                    addon_instance._log_finding(
                        level="WARN",
                        finding_type="Passive Scan - Weak HSTS",
                        url=url,
                        detail=f"HSTS max-age ({max_age}) is less than recommended minimum ({MIN_HSTS_AGE}).",
                        evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
                    )
            except (IndexError, ValueError, TypeError):
                ctx.log.debug(
                    f"Could not parse HSTS max-age from '{hsts_value}' for {url}"
                )
        else:
            # HSTS header present but no max-age? Also potentially weak.
            addon_instance._log_finding(
                level="WARN",
                finding_type="Passive Scan - Weak HSTS",
                url=url,
                detail="HSTS header present but 'max-age' directive is missing.",
                evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
            )

    # X-Content-Type-Options Check (if present)
    xcto_value = present.get("X-Content-Type-Options")
    # Check should be case-insensitive and ignore surrounding whitespace
    if xcto_value is not None and xcto_value.lower().strip() != "nosniff":
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Incorrect X-Content-Type-Options",
            url=url,
            detail=f"X-Content-Type-Options set to '{xcto_value}' instead of recommended 'nosniff'.",
            evidence={"header": f"X-Content-Type-Options: {xcto_value}"},
        )

    # Basic CSP Check (if present)
    csp_value = present.get("Content-Security-Policy")
    # Could also check CSP-Report-Only header?
    if csp_value:
        _check_csp_directives(csp_value, url, addon_instance)


def _check_csp_directives(csp_value: str, url: str, addon_instance: "MainAddon"):
    """Performs basic checks for weak CSP directives. Needs a proper parser for accuracy."""
    # This is a very basic check, a real CSP parser would be much more robust.
    weak_directives_found = []
    csp_lower = csp_value.lower()

    # Check for common unsafe directives
    if "'unsafe-inline'" in csp_lower:
        weak_directives_found.append("'unsafe-inline'")
    if "'unsafe-eval'" in csp_lower:
        weak_directives_found.append("'unsafe-eval'")

    # Basic check for overly broad sources (needs proper parsing for accuracy)
    # Example: checks for '*' alone or http: in script-src/default-src
    # This simple regex might have false positives/negatives.
    if re.search(
        r"(script-src|default-src)\s+([^;]*?\s+\*\s+[^;]*?|[^;]*?'none'[^;]*?\*)",
        csp_lower,
    ):
        weak_directives_found.append("Wildcard (*) source in script-src/default-src")
    if re.search(r"(script-src|default-src)\s+([^;]*?\s+http:\s+[^;]*)", csp_lower):
        weak_directives_found.append("HTTP: source in script-src/default-src")
    if re.search(r"object-src\s+([^;]*?\*[^;]*)", csp_lower):
        weak_directives_found.append("Wildcard (*) source in object-src")
    # Add checks for missing object-src, base-uri etc.

    if weak_directives_found:
        # Log finding using the passed addon instance
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Weak CSP",
            url=url,
            detail=f"Potential weak directives/sources found in CSP: {', '.join(sorted(list(set(weak_directives_found))))}",  # Deduplicate
            evidence={
                "header": f"Content-Security-Policy: {csp_value[:150]}..."
            },  # Log snippet
        )
