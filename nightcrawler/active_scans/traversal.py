# nightcrawler/active_scans/traversal.py
# Active scanner for basic Directory Traversal vulnerabilities.

import httpx
import re
from typing import Dict, Any, List, TYPE_CHECKING, Pattern, Set, Optional
from nightcrawler.active_scans.base import ActiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

TRAVERSAL_PAYLOADS: List[str] = [
    "../", "../../", "../../../", "../../../../", "../../../../../",
    "../../../../../../etc/passwd", "../../../../../windows/win.ini",
    "....//", "..%2f", "..%2f..%2f", "..%5c", "..%5c..%5c", "../%00.txt",
]

SUSPICIOUS_PARAM_NAMES: Set[str] = {
    "file", "page", "path", "document", "doc", "template", "include", "view",
    "dir", "folder", "item", "id", "content", "resource", "name", "filename",
    "conf", "setting", "style", "sheet", "config", "url", "uri", "load", "show",
    "file_path", "filePath",
}

class DirectoryTraversalScanner(ActiveScanner):
    name: str = "Directory Traversal"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """
        Attempts basic directory traversal payloads.
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
            return

        self.logger.debug(f"[Traversal Scan] Starting for {url}. Params to test: {list(params_to_fuzz.keys())}")

        request_headers = {
            k: v for k, v in original_headers.items()
            if k.lower() not in ["content-length", "host", "transfer-encoding", "connection", "cookie"]
        }
        if cookies:
            request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        logged_findings = set()

        for param_name in params_to_fuzz.keys():
            for payload in TRAVERSAL_PAYLOADS:
                finding_key = f"{param_name}::{payload}"
                if finding_key in logged_findings: continue

                current_params, current_data = original_params.copy(), original_data.copy()
                is_in_query = param_name in original_params
                if is_in_query: current_params[param_name] = payload
                else: current_data[param_name] = payload

                try:
                    response = await http_client.request(
                        method, url.split("?")[0] if is_in_query else url,
                        params=current_params if is_in_query else original_params,
                        data=current_data if not is_in_query else original_data,
                        headers=request_headers,
                    )

                    response_text = response.text
                    if not response_text: continue

                    if "root:x:0:0" in response_text or "[extensions]" in response_text or "[fonts]" in response_text:
                        self.addon_instance._log_finding(
                            level="ERROR", finding_type="Directory Traversal Found (Content Match)",
                            url=url, detail=f"Found known file signature in response for param '{param_name}'.",
                            evidence={"param": param_name, "payload": payload, "snippet": response_text[:200]},
                            confidence="HIGH",
                        )
                        logged_findings.add(finding_key)
                        break
                except Exception as e:
                    self.logger.debug(f"[Traversal Scan] Exception for Param: {param_name}, Payload: {payload}: {e}")
