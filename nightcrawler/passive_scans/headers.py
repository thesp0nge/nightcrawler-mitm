# nightcrawler/passive_scans/headers.py
# Passive checks related to HTTP security headers.

import re
from mitmproxy import http
from typing import Dict, TYPE_CHECKING, Any, List

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Headers to check for presence
EXPECTED_SECURITY_HEADERS: List[str] = [
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
INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]
GENERIC_SERVER_VALUES = {"apache", "nginx", "iis", "envoy", "cloudflare"}
SENSITIVE_CONTENT_TYPES = {"application/json", "application/xml", "text/xml"}


def check_security_headers(
    response: http.Response, url: str, addon_instance: "MainAddon", logger: Any
):
    """
    Checks for presence/absence and basic validity of common security headers,
    plus checks for info disclosure, caching, and CORS headers.
    Logs findings using the provided addon_instance.
    """
    headers = response.headers
    present_headers = {}
    missing_std_headers = []

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
    hsts_value = present_headers.get("Strict-Transport-Security")
    if hsts_value:
        _check_hsts_value(hsts_value, url, addon_instance, logger)

    xcto_value = present_headers.get("X-Content-Type-Options")
    if xcto_value is not None and xcto_value.lower().strip() != "nosniff":
        _log_xcto_issue(xcto_value, url, addon_instance)

    csp_value = present_headers.get("Content-Security-Policy")
    if csp_value:
        _check_csp_directives(csp_value, url, addon_instance)

    # --- New Checks ---
    _check_info_disclosure_headers(headers, url, addon_instance, logger)
    _check_caching_headers(response, url, addon_instance)  # Pass full response
    _check_cors_headers(headers, url, addon_instance)


# --- Helper Check Functions ---


def _check_hsts_value(
    hsts_value: str, url: str, addon_instance: "MainAddon", logger: Any
):
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
            logger.debug(f"Could not parse HSTS max-age from '{hsts_value}' for {url}")
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


def _check_csp_directives(csp_value: str, url: str, addon_instance: "MainAddon"):
    """Performs basic checks for weak CSP directives."""
    weak_directives_found = []
    csp_lower = csp_value.lower()
    if "'unsafe-inline'" in csp_lower:
        weak_directives_found.append("'unsafe-inline'")
    if "'unsafe-eval'" in csp_lower:
        weak_directives_found.append("'unsafe-eval'")
    if re.search(r"(script-src|default-src)\s+([^;]*?\s+\*\s+[^;]*)", csp_lower):
        weak_directives_found.append("Wildcard (*) source")
    if re.search(r"(script-src|default-src)\s+([^;]*?\s+http:\s+[^;]*)", csp_lower):
        weak_directives_found.append("HTTP: source")
    if "object-src" not in csp_lower and "default-src" not in csp_lower:
        weak_directives_found.append("Missing object-src/default-src")
    if "base-uri" not in csp_lower:
        weak_directives_found.append("Missing base-uri")
    if weak_directives_found:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Weak CSP",
            url=url,
            detail=f"Potential weak directives/sources found: {', '.join(sorted(list(set(weak_directives_found))))}",
            evidence={"header": f"CSP Header Snippet: {csp_value[:150]}..."},
        )


def _check_info_disclosure_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon", logger: Any
):
    """Checks for headers that might disclose backend technology/versions."""
    for header_name in INFO_DISCLOSURE_HEADERS:
        value = headers.get(header_name)
        if value:
            log_level = "INFO"
            detail = f"Header '{header_name}' present, value: {value[:100]}"
            if header_name == "Server" and value.lower() not in GENERIC_SERVER_VALUES:
                log_level = "WARN"
                detail = f"Potentially specific version disclosed in '{header_name}' header: {value[:100]}"
            elif header_name == "X-Powered-By":
                log_level = "WARN"
                detail = f"Potentially unnecessary info disclosed in '{header_name}': {value[:100]}"
            elif header_name == "Via":
                detail = f"Proxy detected via '{header_name}' header: {value[:100]}"
            addon_instance._log_finding(
                level=log_level,
                finding_type=f"Passive Scan - Info Disclosure ({header_name})",
                url=url,
                detail=detail,
                evidence={"header": f"{header_name}: {value}"},
            )


def _check_caching_headers(
    response: http.Response, url: str, addon_instance: "MainAddon"
):
    """Checks caching headers for potential misconfigurations on sensitive content."""
    headers = response.headers
    cache_control = headers.get("Cache-Control", "").lower()
    pragma = headers.get("Pragma", "").lower()
    content_type = headers.get("Content-Type", "").lower()
    is_sensitive_type = any(ct in content_type for ct in SENSITIVE_CONTENT_TYPES)
    is_public = "public" in cache_control

    if is_public and is_sensitive_type:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Potential Sensitive Data Caching",
            url=url,
            detail=f"'Cache-Control: public' found on potentially sensitive content type '{content_type}'.",
            evidence={"header": f"Cache-Control: {headers.get('Cache-Control')}"},
        )
    elif (
        is_sensitive_type
        and not is_public
        and "no-cache" not in cache_control
        and "no-store" not in cache_control
        and "no-cache" not in pragma
    ):
        addon_instance._log_finding(
            level="INFO",
            finding_type="Passive Scan - Caching Not Disabled?",
            url=url,
            detail=f"Caching not explicitly disabled on potentially sensitive content type '{content_type}'.",
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
            level="WARN",
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
            detail="Access-Control-Allow-Origin is 'null'. This can be insecure.",
            evidence={"header": f"Access-Control-Allow-Origin: {acao_header}"},
        )
