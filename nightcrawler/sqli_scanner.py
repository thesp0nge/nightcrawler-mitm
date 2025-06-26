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
    logger: Any,
):
    """Attempts basic SQLi payloads, logging findings via addon_instance."""
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(f"[SQLi Scan] Starting for {url} with {len(payloads)} payloads.")

    for param_name in params_to_fuzz:
        for payload in payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params

            # --- CORRECTED LOGIC: Handle list values from parse_qs ---
            value = (
                current_params[param_name]
                if is_param_in_query
                else current_data[param_name]
            )
            # If the value is a list (from parse_qs), take the first element.
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""
            # --- END CORRECTION ---

            # Now, original_value is guaranteed to be a string
            if is_param_in_query:
                current_params[param_name] = original_value + payload
            else:
                current_data[param_name] = original_value + payload

            payload_info_detail = f"Param: {param_name}, Payload: {payload}"
            payload_info_evidence = {"param": param_name, "payload": payload}

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
            if cookies:
                request_headers["Cookie"] = "; ".join(
                    [f"{k}={v}" for k, v in cookies.items()]
                )

            try:
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params,
                    data=current_data,
                    headers=request_headers,
                )
                duration = time.time() - start_time

                error_patterns = [
                    "sql syntax",
                    "unclosed quotation",
                    "odbc",
                    "ora-",
                    "invalid sql",
                ]
                response_text_lower = response.text.lower() if response.text else ""
                if any(pattern in response_text_lower for pattern in error_patterns):
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Error-Based)",
                        url=url,
                        detail=payload_info_detail,
                        evidence=payload_info_evidence,
                    )
                if "SLEEP" in payload.upper() and duration > 4.5:
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Time-Based)",
                        url=url,
                        detail=f"{payload_info_detail}, Duration: {duration:.2f}s",
                        evidence=payload_info_evidence,
                    )
            except Exception as e:
                logger.debug(f"[SQLi Scan] Exception: {e} ({payload_info_detail})")
