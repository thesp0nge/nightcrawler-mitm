# nightcrawler/active_scans/open_redirect.py
# Active scanner for Open Redirect vulnerabilities.

import httpx
import time
from typing import Dict, Any, List, TYPE_CHECKING
from urllib.parse import urlparse, urlencode, parse_qs
from nightcrawler.active_scans.base import ActiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class OpenRedirectScanner(ActiveScanner):
    name: str = "Open Redirect"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """
        Attempts to detect Open Redirect vulnerabilities.
        """
        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

        if not params_to_fuzz:
            return

        self.logger.debug(f"[Open Redirect Scan] Starting for {url}")

        test_redirect_url = "https://nightcrawler.test/redirect_test"

        for param_name in params_to_fuzz:
            is_param_in_query = param_name in original_params
            value = (original_params[param_name] if is_param_in_query else original_data[param_name])
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""

            if "http://" in original_value or "https://" in original_value:
                current_params = original_params.copy()
                current_data = original_data.copy()

                if is_param_in_query: current_params[param_name] = test_redirect_url
                else: current_data[param_name] = test_redirect_url
                
                request_headers = {
                    k: v for k, v in original_headers.items()
                    if k.lower() not in ["content-length", "host", "cookie"]
                }
                if cookies:
                    request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

                try:
                    response = await http_client.request(
                        method, url.split("?")[0] if is_param_in_query else url,
                        params=current_params, data=current_data,
                        headers=request_headers, follow_redirects=False
                    )

                    if response.is_redirect:
                        location_header = response.headers.get("Location")
                        if location_header and test_redirect_url in location_header:
                            self.addon_instance._log_finding(
                                level="ERROR", finding_type="Open Redirect Found",
                                url=url, detail=f"Parameter '{param_name}' redirects to '{location_header}'",
                                evidence={
                                    "param": param_name, "injected_url": test_redirect_url,
                                    "redirected_to": location_header, "status_code": response.status_code,
                                },
                                confidence="HIGH",
                            )
                except Exception as e:
                    self.logger.debug(f"[Open Redirect Scan] Exception: {e} ({param_name})")
