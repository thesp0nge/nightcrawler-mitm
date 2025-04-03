# nightcrawler/sqli_scanner.py
# Contains logic for basic SQL Injection active scanning.

import httpx
import time
from mitmproxy import ctx
from typing import Dict, Any, List

# Default payloads are now defined in addon.py and passed in.


async def scan_sqli_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,  # Passed from main addon
    payloads: List[str],  # Accept list of payloads as argument
):
    """
    Attempts basic SQL injection payloads provided in the list by checking
    for common error messages or time delays.
    """
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    # Parameters to fuzz (from GET query and POST form data)
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        ctx.log.debug(f"[SQLi Scan] No parameters found to fuzz for SQLi at {url}")
        return
    if not payloads:  # Check if the passed payload list is empty
        ctx.log.debug(f"[SQLi Scan] No SQLi payloads provided for {url}")
        return

    ctx.log.debug(
        f"[SQLi Scan] Starting scan for {url} with {len(payloads)} payloads (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        # ctx.log.debug(f"[SQLi Scan] Fuzzing parameter SQLi: {param_name}") # Verbose
        for payload in payloads:  # Iterate over passed payloads
            # Create copies of original data to inject the payload
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            # Get original value to append payload to
            original_value = (
                current_params.get(param_name)
                if is_param_in_query
                else current_data.get(param_name, "")
            )

            # Inject payload by appending
            if is_param_in_query:
                current_params[param_name] = original_value + payload
            else:
                current_data[param_name] = original_value + payload

            payload_info = f"URL: {url}, Param: {param_name}, Payload: {payload}"  # For logging findings/errors
            try:
                # ctx.log.debug(f"[SQLi Scan] Sending payload '{payload}' to param '{param_name}'...") # Verbose
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0]
                    if is_param_in_query
                    else url,  # Base URL if modifying query params
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=headers,
                    cookies=cookies,
                )
                duration = time.time() - start_time
                # ctx.log.debug(f"[SQLi Scan] Received response for payload '{payload}' (Status: {response.status_code}, Duration: {duration:.2f}s)") # Verbose

                # --- Basic SQLi Response Analysis ---
                # TODO: Make error patterns configurable via options?
                error_patterns = [
                    "sql syntax",
                    "unclosed quotation",
                    "odbc",
                    "ora-",
                    "invalid sql",
                    "syntax error",
                    "you have an error in your sql",
                    "quoted string not properly terminated",
                    "sqlstate",
                ]
                response_text_lower = ""
                try:
                    # Attempt to decode response as text, ignore errors if binary content
                    response_text_lower = response.text.lower()
                except Exception:
                    pass  # Ignore decoding errors

                # 1. Error-Based Check (Case-insensitive)
                if response_text_lower and any(
                    pattern in response_text_lower for pattern in error_patterns
                ):
                    ctx.log.error(f"[SQLi FOUND? Error-Based] {payload_info}")

                # 2. Time-Based Check (adjust threshold based on payload, e.g., SLEEP(5))
                # Be mindful of network latency variations.
                if (
                    "SLEEP" in payload.upper() and duration > 4.5
                ):  # Threshold near 5s for SLEEP(5)
                    ctx.log.error(
                        f"[SQLi FOUND? Time-Based] {payload_info}, Duration: {duration:.2f}s"
                    )

                # NOTE: Lacks boolean-based, union-based, out-of-band detection. Very limited.

            except httpx.TimeoutException:
                # Timeouts could also indicate time-based SQLi, but less reliable
                ctx.log.warn(f"[SQLi Scan] Timeout sending payload: {payload_info}")
            except Exception as e:
                # Log other exceptions during request/response handling
                ctx.log.debug(
                    f"[SQLi Scan] Exception during payload send/recv: {e} ({payload_info})"
                )

            # Optional: Short pause between payloads?
            # await asyncio.sleep(0.05)

    ctx.log.debug(f"[SQLi Scan] Finished scan for {url}")
