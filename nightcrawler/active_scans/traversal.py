# nightcrawler/active_scans/traversal.py
# Active scanner for basic Directory Traversal vulnerabilities.

import httpx
import re
from typing import Dict, Any, List, TYPE_CHECKING, Pattern, Set, Optional

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Configuration Constants for Traversal Scan ---
TRAVERSAL_PAYLOADS: List[str] = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "..%2f",
    "..%2f..%2f",
    "..\\",
    "..\\..\\",
]
TARGET_FILES: List[str] = ["etc/passwd", "windows/win.ini", "WEB-INF/web.xml", ".env"]
SENSITIVE_CONTENT_PATTERNS: List[Pattern] = [
    re.compile(r"root:x:0:0"),
    re.compile(r"\[boot loader\]"),
    re.compile(r"<web-app"),
    re.compile(r"DB_PASSWORD"),
]
SUSPICIOUS_PARAM_NAMES: Set[str] = {
    "file",
    "page",
    "path",
    "document",
    "doc",
    "template",
    "include",
    "view",
    "id",
    "item",
    "resource",
}


async def scan_directory_traversal(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,  # Accept a logger object
):
    """Attempts basic directory traversal payloads on likely parameters."""
    url = target_info["url"]
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]

    params_to_fuzz: Dict[str, str] = {
        p_name: p_val
        for p_name, p_val in {**original_params, **original_data}.items()
        if p_name.lower() in SUSPICIOUS_PARAM_NAMES
    }
    if not params_to_fuzz:
        return

    logger.debug(
        f"[Traversal Scan] Starting for {url}. Params to test: {list(params_to_fuzz.keys())}"
    )
    full_payloads = [t + f for t in TRAVERSAL_PAYLOADS for f in TARGET_FILES]

    # Prepare Filtered Headers (once)
    request_headers = {
        k: v
        for k, v in original_headers.items()
        if k.lower()
        not in ["content-length", "host", "transfer-encoding", "connection", "cookie"]
    }
    if method == "POST" and "content-type" not in request_headers:
        original_content_type = original_headers.get("content-type")
        if original_content_type and "urlencoded" in original_content_type.lower():
            request_headers["content-type"] = original_content_type
    if cookies:
        request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    logged_findings_for_target_param = set()

    for param_name in params_to_fuzz.keys():
        for payload in full_payloads:
            # ... (logic to inject payload into current_params/current_data) ...
            finding_key = f"{param_name}::{payload}"
            if finding_key in logged_findings_for_target_param:
                continue

            try:
                # ... (send request with httpx, headers=request_headers, no cookies=...) ...
                response = await http_client.request(...)
                # ... (analyze response and call addon_instance._log_finding if hit) ...
            except httpx.TimeoutException:
                logger.warn(
                    f"[Traversal Scan] Timeout for Param: {param_name}, Payload: {payload}"
                )
            except Exception as e:
                logger.debug(
                    f"[Traversal Scan] Exception for Param: {param_name}, Payload: {payload}: {e}"
                )

    logger.debug(f"[Traversal Scan] Finished for {url}")


# End of nightcrawler/active_scans/traversal.py
