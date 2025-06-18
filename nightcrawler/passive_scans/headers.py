# nightcrawler/passive_scans/headers.py
# Passive checks related to HTTP security headers.

import re
from mitmproxy import ctx, http

# from mitmproxy.coretypes.multidict import MultiDictView # Not needed directly here
from typing import Dict, TYPE_CHECKING, Optional, Set, List, Pattern
from urllib.parse import urlparse  # Needed for CORS check helper

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Headers to check for presence (Can be loaded from config later if needed)
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
CSP_REPORT_ONLY_HEADER: str = "Content-Security-Policy-Report-Only"
MIN_HSTS_AGE: int = 15552000  # Approx 6 months in seconds

# Headers potentially disclosing information
INFO_DISCLOSURE_HEADERS: List[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "Via",
]
GENERIC_SERVER_VALUES: Set[str] = {
    "apache",
    "nginx",
    "iis",
    "envoy",
    "cloudflare",
    "lighttpd",
}

# Potentially sensitive content types where caching might be risky
SENSITIVE_CONTENT_TYPES: Set[str] = {
    "application/json",
    "application/xml",
    "text/xml",
    "application/jwt",
}

# --- Main Orchestrator Function ---


def check_security_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """
    Checks for presence/absence and basic validity of common security headers,
    plus checks for info disclosure, caching, and CORS headers.
    Calls helper functions which log findings using the provided addon_instance.
    """
    present_headers = {}
    missing_std_headers = []

    # Check standard security headers
    for header_name in EXPECTED_SECURITY_HEADERS:
        value = headers.get(header_name)
        if value is not None:
            present_headers[header_name] = value
        # Report missing CSP only if Report-Only is also missing
        elif header_name == "Content-Security-Policy" and not headers.get(
            CSP_REPORT_ONLY_HEADER
        ):
            missing_std_headers.append(header_name)
        # Report other missing headers
        elif header_name != "Content-Security-Policy":
            missing_std_headers.append(header_name)

    # Log missing standard headers finding
    if missing_std_headers:
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Missing Header(s)",
            url=url,
            detail=f"Missing Recommended Security Headers: {', '.join(missing_std_headers)}",
            evidence={"missing": missing_std_headers},
        )

    # --- Call helper checks for present standard headers, passing addon_instance ---
    hsts_value = present_headers.get("Strict-Transport-Security")
    if hsts_value:
        _check_hsts_value(hsts_value, url, addon_instance)  # Pass addon_instance

    xcto_value = present_headers.get("X-Content-Type-Options")
    # Check if header exists and value is not exactly 'nosniff' (case-insensitive)
    if xcto_value is not None and xcto_value.lower().strip() != "nosniff":
        _log_xcto_issue(xcto_value, url, addon_instance)  # Pass addon_instance

    csp_value = present_headers.get("Content-Security-Policy")
    if csp_value:
        _check_csp_directives(
            csp_value, url, addon_instance, is_report_only=False
        )  # Pass addon_instance
    csp_report_value = headers.get(CSP_REPORT_ONLY_HEADER)
    if csp_report_value:
        _check_csp_directives(
            csp_report_value, url, addon_instance, is_report_only=True
        )  # Pass addon_instance

    # Check if X-Frame-Options is redundant/missing when frame-ancestors is NOT set in CSP
    if present_headers.get("X-Frame-Options") is None and (
        not csp_value or "frame-ancestors" not in csp_value.lower()
    ):
        # Log informational finding about clickjacking defense status
        addon_instance._log_finding(
            level="INFO",
            finding_type="Passive Scan - Clickjacking Defence?",
            url=url,
            detail="Neither X-Frame-Options header nor CSP frame-ancestors directive found. Potential clickjacking risk.",
            evidence=None,
        )

    # --- Call other checks, passing addon_instance ---
    _check_info_disclosure_headers(headers, url, addon_instance)
    _check_caching_headers(headers, url, addon_instance)
    _check_cors_headers(headers, url, addon_instance)


# --- Helper Check Functions (Now accept addon_instance and use _log_finding) ---


def _check_hsts_value(hsts_value: str, url: str, addon_instance: "MainAddon"):
    """Checks HSTS max-age directive."""
    if "max-age" in hsts_value.lower():
        try:
            max_age_str = hsts_value.lower().split("max-age=")[1].split(";")[0].strip()
            max_age = int(max_age_str)
            if max_age < MIN_HSTS_AGE:
                # Use addon_instance._log_finding for the finding
                addon_instance._log_finding(
                    level="WARN",
                    finding_type="Passive Scan - Weak HSTS",
                    url=url,
                    detail=f"HSTS max-age ({max_age}) is less than recommended minimum ({MIN_HSTS_AGE}).",
                    evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
                )
        except (IndexError, ValueError, TypeError) as e:
            # Use ctx safely for internal debug logs
            try:
                ctx.log.debug(
                    f"Could not parse HSTS max-age from '{hsts_value}' for {url}: {e}"
                )
            except AttributeError:
                pass  # Ignore if ctx.log not available (e.g., pytest)
    else:
        # Use addon_instance._log_finding for the finding
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Weak HSTS",
            url=url,
            detail="HSTS header present but 'max-age' directive is missing.",
            evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
        )


def _log_xcto_issue(xcto_value: str, url: str, addon_instance: "MainAddon"):
    """Logs issue with X-Content-Type-Options header value using the addon logger."""
    # Use addon_instance._log_finding for the finding
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
    """Performs basic checks for weak CSP directives using regex and logs findings."""
    csp_lower = csp_value.lower()
    finding_prefix = "Passive Scan - Weak CSP" + (
        " (Report-Only)" if is_report_only else ""
    )
    header_name = (
        CSP_REPORT_ONLY_HEADER if is_report_only else "Content-Security-Policy"
    )
    evidence = {
        "header": f"{header_name}: {csp_value[:150]}..."
    }  # Common evidence part
    weaknesses_found: List[str] = []  # Collect specific weaknesses found

    try:  # Wrap regex checks
        if "'unsafe-inline'" in csp_lower:
            weaknesses_found.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp_lower:
            weaknesses_found.append("'unsafe-eval'")
        if re.search(
            r"(script-src|default-src|object-src)\s+([^;]*?\s+\*\s+[^;]*?)", csp_lower
        ):
            weaknesses_found.append("Wildcard (*) source")
        if re.search(
            r"(script-src|default-src|object-src)\s+([^;]*?\s+(?:http:|data:)\s+[^;]*)",
            csp_lower,
        ):
            weaknesses_found.append("Insecure Scheme (http:/data:)")
        if "object-src" not in csp_lower and "default-src" not in csp_lower:
            weaknesses_found.append("Missing object-src/default-src")
        if "base-uri" not in csp_lower:
            weaknesses_found.append("Missing base-uri")

        object_src_match = re.search(r"object-src\s+([^;]+)", csp_lower)
        if object_src_match and "'none'" not in object_src_match.group(1):
            weaknesses_found.append(
                f"Insecure object-src ('{object_src_match.group(1).strip()}')"
            )
        base_uri_match = re.search(r"base-uri\s+([^;]+)", csp_lower)
        if (
            base_uri_match
            and "'self'" not in base_uri_match.group(1)
            and "'none'" not in base_uri_match.group(1)
        ):
            weaknesses_found.append("Insecure base-uri")
        frame_ancestors_match = re.search(r"frame-ancestors\s+([^;]+)", csp_lower)
        if (
            frame_ancestors_match
            and "'self'" not in frame_ancestors_match.group(1)
            and "'none'" not in frame_ancestors_match.group(1)
        ):
            weaknesses_found.append("Insecure frame-ancestors")
        form_action_match = re.search(r"form-action\s+([^;]+)", csp_lower)
        if form_action_match and "'self'" not in form_action_match.group(1):
            weaknesses_found.append("Broad form-action")

    except Exception as e:
        # Use ctx safely for internal debug logs
        try:
            ctx.log.debug(f"Regex error during CSP check for {url}: {e}")
        except AttributeError:
            pass

    # Log finding if any weaknesses were detected
    if weaknesses_found:
        # Use addon_instance._log_finding for the finding
        addon_instance._log_finding(
            level="WARN",
            finding_type=finding_prefix,
            url=url,
            detail=f"Potential weak directives/sources found: {', '.join(sorted(list(set(weaknesses_found))))}",  # Deduplicate and sort
            evidence=evidence,
        )


def _check_info_disclosure_headers(
    headers: http.Headers, url: str, addon_instance: "MainAddon"
):
    """Checks for headers that might disclose backend technology/versions."""
    for header_name in INFO_DISCLOSURE_HEADERS:
        value = headers.get(header_name)
        if value:
            log_level = "INFO"
            detail = f"Header '{header_name}' present, value: {value[:100]}"
            is_verbose = False
            try:  # Check for verbose patterns safely
                if header_name == "Server":
                    server_name_lower = (
                        value.split("/")[0].split("(")[0].strip().lower()
                    )
                    is_verbose = bool(
                        server_name_lower not in GENERIC_SERVER_VALUES
                        and server_name_lower != ""
                        or ("/" in value or "(" in value)
                    )
                elif header_name == "X-Powered-By" or header_name == "X-AspNet-Version":
                    is_verbose = True
            except Exception as e:  # Catch potential errors in string splitting etc.
                try:
                    ctx.log.debug(
                        f"Error checking verbosity for header {header_name}: {e}"
                    )
                except AttributeError:
                    pass

            if is_verbose:
                log_level = "WARN"
                detail = f"Potentially verbose info in '{header_name}': {value[:100]}"
            # Use addon_instance._log_finding for the finding
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
    is_sensitive_type = any(
        ct in content_type for ct in SENSITIVE_CONTENT_TYPES
    ) or url.endswith((".js", ".json"))  # Basic check

    # Check 1: Public caching explicitly enabled on sensitive type
    if "public" in cache_control and is_sensitive_type:
        # Use addon_instance._log_finding for the finding
        addon_instance._log_finding(
            level="WARN",
            finding_type="Passive Scan - Potential Sensitive Data Caching",
            url=url,
            detail=f"'Cache-Control: public' on sensitive type '{content_type}'.",
            evidence={
                "header_cache": headers.get("Cache-Control"),
                "header_content": headers.get("Content-Type"),
            },
        )

    # Check 2: Caching not explicitly disabled on sensitive type
    elif (
        is_sensitive_type
        and "no-cache" not in cache_control
        and "no-store" not in cache_control
        and "no-cache" not in pragma
    ):
        # Use addon_instance._log_finding for the finding
        addon_instance._log_finding(
            level="INFO",
            finding_type="Passive Scan - Caching Not Explicitly Disabled?",
            url=url,
            detail=f"Caching not explicitly disabled on sensitive type '{content_type}'. Review policy.",
            evidence={
                "Cache-Control": headers.get("Cache-Control"),
                "Pragma": headers.get("Pragma"),
            },
        )


def _check_cors_headers(headers: http.Headers, url: str, addon_instance: "MainAddon"):
    """Checks Access-Control-Allow-Origin header for permissive values."""
    acao_header = headers.get("Access-Control-Allow-Origin")
    if acao_header is None:
        return  # Header not present

    log_level = "WARN"
    finding_detail = ""
    finding_type_suffix = ""
    if acao_header == "*":
        finding_type_suffix = "(Wildcard)"
        finding_detail = "ACAO is wildcard (*), allowing read access from any origin."
    elif acao_header.lower() == "null":
        finding_type_suffix = "(Null)"
        finding_detail = "ACAO is 'null', potentially insecure."
    # Check for reflected Origin + Credentials (basic check)
    elif headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
        try:
            # Compare ACAO to the request's own host. If different and creds allowed = risky.
            request_host = urlparse(url).hostname
            # Check if ACAO is not the same origin and not a wildcard/null (already checked)
            if request_host and request_host != acao_header:
                log_level = "INFO"
                finding_type_suffix = "(Credentials + Specific Origin?)"
                finding_detail = f"ACAO set to specific origin '{acao_header}' with Credentials=true. Verify reflection possibility."
        except Exception as e:
            # Use ctx safely for internal debug logs
            try:
                ctx.log.debug(f"Error parsing URL for CORS check: {e}")
            except AttributeError:
                pass

    if finding_detail:
        # Use addon_instance._log_finding for the finding
        addon_instance._log_finding(
            level=log_level,
            finding_type=f"Passive Scan - Permissive CORS {finding_type_suffix}",
            url=url,
            detail=finding_detail,
            evidence={
                "ACAO": acao_header,
                "ACAC": headers.get("Access-Control-Allow-Credentials"),
            },
        )


# End of nightcrawler/passive_scans/headers.py
