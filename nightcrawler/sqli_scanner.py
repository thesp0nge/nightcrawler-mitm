# nightcrawler/sqli_scanner.py
# Contains logic for basic SQL Injection active scanning.

import httpx
import time
from mitmproxy import ctx
from typing import Dict, Any, List, TYPE_CHECKING

# Type hint for MainAddon
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_sqli_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,  # Passed from main addon
    payloads: List[str],  # Accept list of payloads as argument
    addon_instance: "MainAddon",  # Added addon_instance for logging
):
    """
    Attempts basic SQL injection payloads provided in the list by checking
    for common error messages or time delays. Filters problematic headers.
    Logs findings via addon_instance.
    """
    url = target_info["url"]
    method = target_info["method"].upper()  # Ensure method is uppercase
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]  # Get original headers
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    if not payloads:
        return

    # ctx.log.debug(f"[SQLi Scan] Starting scan for {url}...") # Caller logs this

    for param_name in params_to_fuzz:
        # ctx.log.debug(f"[SQLi Scan] Fuzzing parameter SQLi: {param_name}") # Verbose
        for payload in payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            original_value = (
                current_params.get(param_name)
                if is_param_in_query
                else current_data.get(param_name, "")
            )
            # Append payload for SQLi checks
            if is_param_in_query:
                current_params[param_name] = original_value + payload
            else:
                current_data[param_name] = original_value + payload

            payload_info_detail = f"Param: {param_name}, Payload: {payload}"
            payload_info_evidence = {"param": param_name, "payload": payload}

            # --- Prepare Filtered Headers ---
            request_headers = {
                k: v
                for k, v in original_headers.items()
                if k.lower() not in ["content-length", "host", "transfer-encoding"]
            }
            # Ensure Content-Type is preserved for relevant POST methods
            if method == "POST" and "content-type" not in request_headers:
                original_content_type = original_headers.get("content-type")
                if (
                    original_content_type and "urlencoded" in original_content_type
                ):  # Or check other relevant types if needed
                    request_headers["content-type"] = original_content_type
            # --- End Header Preparation ---

            try:
                # ctx.log.debug(f"[SQLi Scan] Sending payload '{payload}' to param '{param_name}'...") # Verbose
                start_time = time.time()
                # Send request using filtered headers
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=request_headers,  # <-- USE FILTERED HEADERS
                    cookies=cookies,
                )
                duration = time.time() - start_time
                # ctx.log.debug(f"[SQLi Scan] Received response (Status: {response.status_code}, Duration: {duration:.2f}s)") # Verbose

                # --- SQLi Response Analysis & Logging via Addon ---
                error_patterns = [
                    "sql syntax",
                    "unclosed quotation",
                    "odbc",
                    "ora-",
                    "invalid sql",
                    "syntax error",
                    "you have an error in your sql",
                ]
                response_text_lower = ""
                try:
                    response_text_lower = response.text.lower()
                except Exception:
                    pass

                if response_text_lower and any(
                    pattern in response_text_lower for pattern in error_patterns
                ):
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Error-Based)",
                        url=url,
                        detail=payload_info_detail,
                        evidence=payload_info_evidence,
                    )
                if (
                    "SLEEP" in payload.upper() and duration > 4.5
                ):  # Adjust threshold as needed
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Time-Based)",
                        url=url,
                        detail=f"{payload_info_detail}, Duration: {duration:.2f}s",
                        evidence=payload_info_evidence,
                    )

            except httpx.TimeoutException:
                addon_instance._log_finding(
                    level="WARN",
                    finding_type="SQLi Scan Timeout",
                    url=url,
                    detail=f"Timeout sending payload. {payload_info_detail}",
                    evidence=payload_info_evidence,
                )
            except Exception as e:
                ctx.log.debug(
                    f"[SQLi Scan] Exception during payload send/recv: {e} ({payload_info_detail})"
                )

    # ctx.log.debug(f"[SQLi Scan] Finished scan for {url}") # Caller logs this


# End of nightcrawler/sqli_scanner.@property
