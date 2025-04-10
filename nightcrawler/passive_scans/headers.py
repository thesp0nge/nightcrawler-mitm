# nightcrawler/passive_scans/headers.py
# Passive checks related to HTTP security headers.

import re
from mitmproxy import ctx, http
from mitmproxy.coretypes.multidict import (
    MultiDictView,
)  # Keep for cookie checks if moved here later
from typing import Dict, TYPE_CHECKING, Optional, Set

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Headers to check for presence
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

# Headers potentially disclosing information
INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]
# Generic values often used to hide specific versions
GENERIC_SERVER_VALUES = {"apache", "nginx", "iis", "envoy", "cloudflare"}

# Potentially sensitive content types where public caching might be risky
SENSITIVE_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "text/xml",
}  # Add others? text/html?


def check_security_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """
    Checks for presence/absence and basic validity of common security headers,
    plus checks for info disclosure, caching, and CORS headers.
    Logs findings using the provided addon_instance.
    """
    present_headers = {}
    missing_std_headers = []

    # Check standard security headers
    for header_name in EXPECTED_SECURITY_HEADERS:
        value = headers.get(header_name)
        if value is not None:
            present_headers[header_name] = value
        elif header_name == "Content-Security-Policy" and not headers.get(
            CSP_REPORT_ONLY_HEADER
        ):
            missing_std_headers.append(header_name)
        elif header_name != "Content-Security-Policy":
            missing_std_headers.append(header_name)

    if missing_std_headers:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Missing Header(s)",
            url=url,
            detail=f"Missing Recommended Security Headers: {', '.join(missing_std_headers)}",
            evidence={"missing": missing_std_headers},
        )

    # --- Basic checks for present standard headers ---
    # HSTS Check
    hsts_value = present_headers.get("Strict-Transport-Security")
    if hsts_value:
        _check_hsts_value(hsts_value, url, addon_instance)

    # X-Content-Type-Options Check
    xcto_value = present_headers.get("X-Content-Type-Options")
    if xcto_value is not None and xcto_value.lower().strip() != "nosniff":
        _log_xcto_issue(xcto_value, url, addon_instance)

    # Basic CSP Check
    csp_value = present_headers.get("Content-Security-Policy")
    if csp_value:
        _check_csp_directives(csp_value, url, addon_instance)
    # Optionally check CSP-Report-Only too?
    # csp_report_value = headers.get(CSP_REPORT_ONLY_HEADER)
    # if csp_report_value: _check_csp_directives(csp_report_value, url, addon_instance, is_report_only=True)

    # --- New Checks ---
    # Information Disclosure Headers
    _check_info_disclosure_headers(headers, url, addon_instance)

    # Caching Headers Check
    _check_caching_headers(headers, url, addon_instance)

    # CORS Headers Check
    _check_cors_headers(headers, url, addon_instance)


# --- Helper Check Functions ---


def _check_hsts_value(hsts_value: str, url: str, addon_instance: "MainAddon"):
    """Checks HSTS max-age directive."""
    if "max-age" in hsts_value.lower():
        try:
            max_age_str = hsts_value.lower().split("max-age=")[1].split(";")[0].strip()
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
            ctx.log.debug(f"Could not parse HSTS max-age from '{hsts_value}' for {url}")
    else:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Weak HSTS",
            url=url,
            detail="HSTS header present but 'max-age' directive is missing.",
            evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
        )


def _log_xcto_issue(xcto_value: str, url: str, addon_instance: "MainAddon"):
    """Logs issue with X-Content-Type-Options header value."""
    addon_instance._log_finding(
        level="WARN",
        finding_type="Passive Scan - Incorrect X-Content-Type-Options",
        url=url,
        detail=f"X-Content-Type-Options set to '{xcto_value}' instead of recommended 'nosniff'.",
        evidence={"header": f"X-Content-Type-Options: {xcto_value}"},
    )


def _check_csp_directives(
    csp_value: str, url: str, addon_instance: "MainAddon", is_report_only=False
):
    """Performs basic checks for weak CSP directives."""
    weak_directives_found = []
    csp_lower = csp_value.lower()
    finding_prefix = (
        "Passive Scan - Weak CSP"
        if not is_report_only
        else "Passive Scan - Weak CSP (Report-Only)"
    )

    if "'unsafe-inline'" in csp_lower:
        weak_directives_found.append("'unsafe-inline'")
    if "'unsafe-eval'" in csp_lower:
        weak_directives_found.append("'unsafe-eval'")
    # Basic regex checks for wildcards or http: (needs proper parser for accuracy)
    if re.search(
        r"(script-src|default-src)\s+([^;]*?\s+\*\s+[^;]*?|[^;]*?'none'[^;]*?\*)",
        csp_lower,
    ):
        weak_directives_found.append("Wildcard (*) source")
    if re.search(r"(script-src|default-src)\s+([^;]*?\s+http:\s+[^;]*)", csp_lower):
        weak_directives_found.append("HTTP: source")
    if re.search(r"object-src\s+([^;]*?\*[^;]*)", csp_lower):
        weak_directives_found.append("Wildcard object-src")
    # Check for missing object-src or default-src which can be risky
    if "object-src" not in csp_lower and "default-src" not in csp_lower:
        weak_directives_found.append("Missing object-src/default-src")
    # Check for missing base-uri
    if "base-uri" not in csp_lower:
        weak_directives_found.append("Missing base-uri")

    if weak_directives_found:
        addon_instance._log_finding(
            level="WARN",
            finding_type=finding_prefix,
            url=url,
            detail=f"Potential weak directives/sources found: {', '.join(sorted(list(set(weak_directives_found))))}",
            evidence={"header": f"CSP Header Snippet: {csp_value[:150]}..."},
        )


def _check_info_disclosure_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """Checks for headers that might disclose backend technology/versions."""
    for header_name in INFO_DISCLOSURE_HEADERS:
        value = headers.get(header_name)
        if value:
            # Basic check: log if present, potentially warn if it contains version info
            log_level = "INFO"
            detail = f"Header '{header_name}' present, value: {value[:100]}"  # Limit logged value length
            # Try to detect specific versions to potentially raise severity
            if (
                header_name == "Server"
                and value.lower() not in GENERIC_SERVER_VALUES
                and ("/" in value or "(" in value)
            ):
                log_level = "WARN"
                detail = f"Potentially specific version disclosed in '{header_name}' header: {value[:100]}"
            elif header_name == "X-Powered-By":
                log_level = "WARN"  # Usually discloses unnecessary info
                detail = f"Potentially unnecessary info disclosed in '{header_name}': {value[:100]}"
            elif header_name == "Via":
                detail = f"Proxy detected via '{header_name}' header: {value[:100]}"  # Info level is fine

            addon_instance._log_finding(
                level=log_level,
                finding_type=f"Passive Scan - Info Disclosure ({header_name})",
                url=url,
                detail=detail,
                evidence={"header": f"{header_name}: {value}"},
            )


def _check_caching_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """Checks caching headers for potential misconfigurations on sensitive content."""
    cache_control = headers.get("Cache-Control", "").lower()
    pragma = headers.get("Pragma", "").lower()
    content_type = headers.get("Content-Type", "").lower()

    # Check 1: Public caching explicitly enabled
    is_public = "public" in cache_control
    is_sensitive_type = any(
        ct in content_type for ct in SENSITIVE_CONTENT_TYPES
    )  # Basic content type check

    if is_public and is_sensitive_type:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Potential Sensitive Data Caching",
            url=url,
            detail=f"'Cache-Control: public' found on potentially sensitive content type '{content_type}'.",
            evidence={"header": f"Cache-Control: {headers.get('Cache-Control')}"},
        )

    # Check 2: Caching not explicitly disabled (more prone to FPs)
    # Only check if not explicitly public and seems sensitive
    elif is_sensitive_type and not is_public:
        no_cache = "no-cache" in cache_control or "no-cache" in pragma
        no_store = "no-store" in cache_control
        # If potentially sensitive and caching not explicitly disabled by no-cache or no-store
        if not no_cache and not no_store:
            addon_instance._log_finding(
                level="INFO",  # Lower severity as browser/proxy defaults vary
                finding_type="Passive Scan - Caching Not Disabled?",
                url=url,
                detail=f"Caching not explicitly disabled (no-cache/no-store) on potentially sensitive content type '{content_type}'. Verify cache headers.",
                evidence={
                    "Cache-Control": headers.get("Cache-Control"),
                    "Pragma": headers.get("Pragma"),
                },
            )


def _check_cors_headers(headers: http.Headers, url: str, addon_instance: "MainAddon"):
    """Checks Access-Control-Allow-Origin header for permissive values."""
    acao_header = headers.get("Access-Control-Allow-Origin")

    if acao_header == "*":
        addon_instance._log_finding(
            level="WARN",  # Wildcard is often problematic
            finding_type="Passive Scan - Permissive CORS (Wildcard)",
            url=url,
            detail="Access-Control-Allow-Origin is wildcard (*), allowing any origin.",
            evidence={"header": f"Access-Control-Allow-Origin: {acao_header}"},
        )
    elif acao_header == "null":
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Permissive CORS (Null)",
            url=url,
            detail="Access-Control-Allow-Origin is 'null'. This can be insecure in some contexts.",
            evidence={"header": f"Access-Control-Allow-Origin: {acao_header}"},
        )
    # More advanced check: if ACAO reflects Origin and Allow-Credentials is true
    # requires access to request headers too, more complex to implement here.
    # elif acao_header and headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
    #     # Check if acao_header looks like a reflected Origin (needs request context)
    #     pass


# End of nightcrawler/passive_scans/headers.py
