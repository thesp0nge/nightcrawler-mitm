# nightcrawler/sqli_scanner.py
# Contains logic for basic SQL Injection active scanning.

import httpx
import time
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_sqli_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
    logger: Any,  # Accept a logger object
):
    """Attempts basic SQLi payloads, logging findings via addon_instance."""
    url = target_info["url"]
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(f"[SQLi Scan] Starting for {url} with {len(payloads)} payloads.")

    for param_name in params_to_fuzz:
        for payload in payloads:
            # ... (logic to inject payload into current_params/current_data) ...
            payload_info_detail = f"Param: {param_name}, Payload: {payload}"
            payload_info_evidence = {"param": param_name, "payload": payload}

            # Prepare Filtered Headers + Cookie Header
            request_headers = {
                k: v
                for k, v in original_headers.items()
                if k.lower()
                not in [
                    "content-length",
                    "host",
                    "transfer-encoding",
                    "connection",
                    "cookie",
                ]
            }
            if method == "POST" and "content-type" not in request_headers:
                original_content_type = original_headers.get("content-type")
                if (
                    original_content_type
                    and "urlencoded" in original_content_type.lower()
                ):
                    request_headers["content-type"] = original_content_type
            if cookies:
                request_headers["Cookie"] = "; ".join(
                    [f"{k}={v}" for k, v in cookies.items()]
                )

            try:
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0] if param_name in original_params else url,
                    params=current_params
                    if param_name in original_params
                    else original_params,
                    data=current_data if param_name in original_data else original_data,
                    headers=request_headers,
                    # No cookies= argument
                )
                duration = time.time() - start_time

                # ... (response analysis logic for error-based and time-based SQLi) ...
                # ... (call addon_instance._log_finding on hits) ...

            except httpx.TimeoutException:
                addon_instance._log_finding(
                    level="WARN",
                    finding_type="SQLi Scan Timeout",
                    url=url,
                    detail=f"Timeout sending payload. {payload_info_detail}",
                    evidence=payload_info_evidence,
                )
            except Exception as e:
                logger.debug(
                    f"[SQLi Scan] Exception during payload send/recv: {e} ({payload_info_detail})"
                )


# End of nightcrawler/sqli_scanner.py
