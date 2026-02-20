# nightcrawler/passive_scans/headers.py
# Passive checks related to HTTP security headers.

import re
from mitmproxy import http
from typing import Dict, TYPE_CHECKING, Any, List, Optional
from nightcrawler.passive_scans.base import PassiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Configuration Constants for Header Checks ---
EXPECTED_SECURITY_HEADERS: List[str] = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy",
]
CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only"
MIN_HSTS_AGE: int = 15552000
INFO_DISCLOSURE_HEADERS: List[str] = ["Server", "X-Powered-By", "X-AspNet-Version", "Via"]
GENERIC_SERVER_VALUES = {"apache", "nginx", "iis", "envoy", "cloudflare"}
SENSITIVE_CONTENT_TYPES = {"application/json", "application/xml", "text/xml"}

class HeaderScanner(PassiveScanner):
    name: str = "Headers"

    async def scan_response(self, response: http.Response, url: str):
        """Orchestrates all passive header checks."""
        headers = response.headers
        present_headers = {}
        missing_std_headers = []

        for header_name in EXPECTED_SECURITY_HEADERS:
            value = headers.get(header_name)
            if value is not None:
                present_headers[header_name] = value
            elif header_name == "Content-Security-Policy" and not headers.get(CSP_REPORT_ONLY_HEADER):
                missing_std_headers.append(header_name)
            elif header_name != "Content-Security-Policy":
                missing_std_headers.append(header_name)

        if missing_std_headers:
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - Missing Header(s)", url=url,
                detail=f"Missing Recommended Security Headers: {', '.join(missing_std_headers)}",
                evidence={"missing": missing_std_headers},
            )

        if hsts_value := present_headers.get("Strict-Transport-Security"):
            self._check_hsts_value(hsts_value, url)
        if xcto_value := present_headers.get("X-Content-Type-Options"):
            if xcto_value.lower().strip() != "nosniff":
                self._log_xcto_issue(xcto_value, url)

        if csp_value := present_headers.get("Content-Security-Policy"):
            self._check_csp_directives(csp_value, url, is_report_only=False)
        if csp_report_value := headers.get(CSP_REPORT_ONLY_HEADER):
            self._check_csp_directives(csp_report_value, url, is_report_only=True)

        self._check_info_disclosure_headers(headers, url)
        self._check_caching_headers(response, url)
        self._check_cors_headers(headers, url)

    def _check_hsts_value(self, hsts_value: str, url: str):
        """Checks HSTS max-age directive."""
        if "max-age" in hsts_value.lower():
            try:
                max_age = int(hsts_value.lower().split("max-age=")[1].split(";")[0].strip())
                if max_age < MIN_HSTS_AGE:
                    self.addon_instance._log_finding(
                        level="WARN", finding_type="Passive Scan - Weak HSTS", url=url,
                        detail=f"HSTS max-age ({max_age}) is less than recommended.",
                        evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
                    )
            except (IndexError, ValueError):
                self.logger.debug(f"Could not parse HSTS max-age from '{hsts_value}' for {url}")
        else:
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - Weak HSTS", url=url,
                detail="HSTS header present but 'max-age' directive is missing.",
                evidence={"header": f"Strict-Transport-Security: {hsts_value}"},
            )

    def _log_xcto_issue(self, xcto_value: str, url: str):
        """Logs issue with X-Content-Type-Options header value."""
        self.addon_instance._log_finding(
            level="WARN", finding_type="Passive Scan - Incorrect X-Content-Type-Options", url=url,
            detail=f"X-Content-Type-Options set to '{xcto_value}' instead of 'nosniff'.",
            evidence={"header": f"X-Content-Type-Options: {xcto_value}"},
        )

    def _check_csp_directives(self, csp_value: str, url: str, is_report_only: bool = False):
        """Performs deeper checks for common weak CSP directives."""
        weaknesses_found = set()
        csp_lower = csp_value.lower()
        finding_prefix = "Passive Scan - Weak CSP" if not is_report_only else "Passive Scan - Weak CSP (Report-Only)"

        if "'unsafe-inline'" in csp_lower: weaknesses_found.add("'unsafe-inline'")
        if "'unsafe-eval'" in csp_lower: weaknesses_found.add("'unsafe-eval'")

        try:
            directives = {
                d.strip().split(None, 1)[0]: d.strip().split(None, 1)[1] if " " in d else ""
                for d in csp_lower.split(";") if d.strip()
            }
            for directive_name, directive_value in directives.items():
                if directive_name in ["script-src", "default-src", "style-src", "connect-src", "img-src", "font-src"]:
                    sources = set(directive_value.split())
                    if "*" in sources: weaknesses_found.add(f"Wildcard (*) source in '{directive_name}'")
                    if "data:" in sources: weaknesses_found.add(f"Broad source ('data:') in '{directive_name}'")
                    if "http:" in sources: weaknesses_found.add(f"Insecure source ('http:') in '{directive_name}'")
            if "object-src" not in directives and "default-src" not in directives:
                weaknesses_found.add("Missing 'object-src' or 'default-src'")
            if "base-uri" not in directives: weaknesses_found.add("Missing 'base-uri'")
            if "frame-ancestors" not in directives: weaknesses_found.add("Missing 'frame-ancestors' directive")
        except Exception as e:
            self.logger.warn(f"Could not parse CSP header for {url}: {e}")

        if weaknesses_found:
            self.addon_instance._log_finding(
                level="WARN", finding_type=finding_prefix, url=url,
                detail=f"Potential weaknesses found in CSP: {', '.join(sorted(list(weaknesses_found)))}",
                evidence={"header": f"CSP: {csp_value[:150]}..."},
            )

    def _check_info_disclosure_headers(self, headers: http.Headers, url: str):
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
                self.addon_instance._log_finding(
                    level=log_level, finding_type=f"Passive Scan - Info Disclosure ({header_name})",
                    url=url, detail=detail, evidence={"header": f"{header_name}: {value}"},
                )

    def _check_caching_headers(self, response: http.Response, url: str):
        """Checks caching headers for potential misconfigurations."""
        headers = response.headers
        cache_control = headers.get("Cache-Control", "").lower()
        pragma = headers.get("Pragma", "").lower()
        content_type = headers.get("Content-Type", "").lower()
        is_sensitive_type = any(ct in content_type for ct in SENSITIVE_CONTENT_TYPES)
        is_public = "public" in cache_control
        if is_public and is_sensitive_type:
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - Potential Sensitive Data Caching", url=url,
                detail=f"'Cache-Control: public' found on potentially sensitive content type '{content_type}'.",
                evidence={"header": f"Cache-Control: {headers.get('Cache-Control')}"},
            )
        elif (is_sensitive_type and not is_public and "no-cache" not in cache_control and
              "no-store" not in cache_control and "no-cache" not in pragma):
            self.addon_instance._log_finding(
                level="INFO", finding_type="Passive Scan - Caching Not Disabled?", url=url,
                detail=f"Caching not explicitly disabled on potentially sensitive content type '{content_type}'.",
                evidence={"Cache-Control": headers.get("Cache-Control"), "Pragma": headers.get("Pragma")},
            )

    def _check_cors_headers(self, headers: http.Headers, url: str):
        """Checks Access-Control-Allow-Origin header for permissive values."""
        acao_header = headers.get("Access-Control-Allow-Origin")
        if acao_header == "*":
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - Permissive CORS (Wildcard)", url=url,
                detail="Access-Control-Allow-Origin is wildcard (*), allowing any origin.",
                evidence={"header": f"Access-Control-Allow-Origin: {acao_header}"},
            )
        elif acao_header == "null":
            self.addon_instance._log_finding(
                level="WARN", finding_type="Passive Scan - Permissive CORS (Null)", url=url,
                detail="Access-Control-Allow-Origin is 'null'. This can be insecure.",
                evidence={"header": f"Access-Control-Allow-Origin: {acao_header}"},
            )
