# nightcrawler/active_scans/traversal.py
# Active scanner for basic Directory Traversal vulnerabilities based on status codes.

import httpx
import re
from typing import Dict, Any, List, TYPE_CHECKING, Pattern, Set, Optional

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Configuration for Traversal Scan ---
# Payloads are now simpler, as we don't need to guess content, just paths.
TRAVERSAL_PAYLOADS: List[str] = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../etc/passwd",
    "../../../../../windows/win.ini",
    "....//",  # Filter evasion
    "..%2f",
    "..%2f..%2f",  # URL encoding
    "..%5c",
    "..%5c..%5c",  # URL encoding for Windows
    "../%00.txt",  # Null byte
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
}

# --- Scanner Function ---


async def scan_directory_traversal(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Attempts basic directory traversal payloads on likely parameters.
    Logs findings based on non-404 HTTP status codes.
    """
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]

    params_to_fuzz = {
        p_name: p_val
        for p_name, p_val in {**original_params, **original_data}.items()
        if p_name.lower() in SUSPICIOUS_PARAM_NAMES
    }
    if not params_to_fuzz:
        logger.debug(
            f"[Traversal Scan] No suspicious parameters found for {url}, skipping."
        )
        return

    logger.debug(
        f"[Traversal Scan] Starting for {url}. Params to test: {list(params_to_fuzz.keys())}"
    )

    request_headers = {
        k: v
        for k, v in original_headers.items()
        if k.lower()
        not in ["content-length", "host", "transfer-encoding", "connection", "cookie"]
    }
    if cookies:
        request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    logged_findings = set()

    for param_name in params_to_fuzz.keys():
        for payload in TRAVERSAL_PAYLOADS:
            # Create a unique key for this specific attack attempt
            finding_key = f"{param_name}::{payload}"
            if finding_key in logged_findings:
                continue

            current_params, current_data = original_params.copy(), original_data.copy()
            is_in_query = param_name in original_params
            if is_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            try:
                # Use the original request's method for the traversal attempt
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_in_query else url,
                    params=current_params if is_in_query else original_params,
                    data=current_data if not is_in_query else original_data,
                    headers=request_headers,
                )

                # --- NEW LOGIC: Analyze Response Status Code ---
                status_code = response.status_code
                if status_code != 404:
                    level = "ERROR" if 200 <= status_code < 300 else "WARN"
                    finding_type = "Directory Traversal? (Status Code)"

                    addon_instance._log_finding(
                        level=level,
                        finding_type=finding_type,
                        url=url,
                        detail=f"Received status {status_code} for traversal attempt on param '{param_name}'.",
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "response_status": status_code,
                        },
                    )
                    logged_findings.add(finding_key)
                    # We can break after the first non-404 for this parameter to reduce noise
                    break

            except Exception as e:
                logger.debug(
                    f"[Traversal Scan] Exception for Param: {param_name}, Payload: {payload}: {e}"
                )

    logger.debug(f"[Traversal Scan] Finished for {url}")
