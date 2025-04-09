# nightcrawler/xss_scanner.py
import httpx
import time
import random
from mitmproxy import ctx
from typing import Dict, Any, List, TYPE_CHECKING

# Import default payloads only as fallbacks if needed, main config from options
# from nightcrawler.config import DEFAULT_XSS_REFLECTED_PAYLOADS, DEFAULT_XSS_STORED_PREFIX, DEFAULT_XSS_STORED_FORMAT # Not needed directly here

# Type hint for MainAddon without causing circular import during type checking
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Reflected XSS Scan ---


async def scan_xss_reflected_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],  # Accept list of payloads as argument
    addon_instance: "MainAddon",  # Accept addon_instance for logging
):
    """
    Attempts basic reflected XSS payloads provided in the list by checking
    for immediate, exact reflection in the HTML response.
    Filters problematic headers before sending requests.
    Logs findings using the provided addon_instance.
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
        ctx.log.debug(
            f"[XSS Reflected Scan] No reflected XSS payloads provided for {url}"
        )
        return

    # ctx.log.debug(f"[XSS Reflected Scan] Starting for {url}...") # Caller logs this

    for param_name in params_to_fuzz:
        # ctx.log.debug(f"[XSS Reflected Scan] Fuzzing parameter: {param_name}") # Verbose
        for payload in payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            payload_info_detail = (
                f"Param: {param_name}, Payload Snippet: {payload[:50]}..."
            )
            payload_info_evidence = {"param": param_name, "payload": payload[:100]}

            # --- Prepare Filtered Headers ---
            request_headers = {
                k: v
                for k, v in original_headers.items()
                # Filter out headers that httpx should manage or that cause issues
                if k.lower() not in ["content-length", "host", "transfer-encoding"]
            }
            # Ensure Content-Type is preserved for relevant POST methods
            if method == "POST" and "content-type" not in request_headers:
                original_content_type = original_headers.get("content-type")
                # Add it back only if it was originally present and relevant (e.g., urlencoded)
                if original_content_type and "urlencoded" in original_content_type:
                    request_headers["content-type"] = original_content_type
            # --- End Header Preparation ---

            try:
                # Send request using the FILTERED headers
                response = await http_client.request(
                    method,
                    url.split("?")[0]
                    if is_param_in_query
                    else url,  # Base URL if modifying query params
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=request_headers,  # <-- USA GLI HEADER FILTRATI
                    cookies=cookies,
                )

                # --- Basic Reflected XSS Response Analysis ---
                content_type = response.headers.get("Content-Type", "")
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text
                    except Exception:
                        pass
                    # Check for reflection
                    reflection_check_result = False
                    if response_text:
                        reflection_check_result = payload in response_text
                    # Log finding if reflected
                    if reflection_check_result:
                        addon_instance._log_finding(
                            level="ERROR",
                            finding_type="XSS Found? (Reflected)",
                            url=url,
                            detail=payload_info_detail,
                            evidence=payload_info_evidence,
                        )
            except httpx.TimeoutException:
                addon_instance._log_finding(
                    level="WARN",
                    finding_type="XSS Reflected Scan Timeout",
                    url=url,
                    detail=f"Timeout sending payload. {payload_info_detail}",
                    evidence=payload_info_evidence,
                )
            except Exception as e:
                # Log other exceptions (should not be Content-Length now)
                ctx.log.debug(
                    f"[XSS Reflected Scan] Exception during payload send/recv: {e} ({payload_info_detail})"
                )


# --- Stored XSS Injection Attempt ---


async def scan_xss_stored_inject(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",  # Pass addon instance for state access
    probe_prefix: str,  # Pass configured prefix
    payload_format: str,  # Pass configured format string
):
    """
    Injects unique, trackable payloads into parameters using the provided prefix
    and format string, then registers the injection attempt with the main addon.
    Filters problematic headers before sending requests.
    """
    url = target_info["url"]
    method = target_info["method"].upper()  # Ensure method is uppercase
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]  # Get original headers
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    # Validate format string contains the placeholder before starting loop
    if "{probe_id}" not in payload_format:
        # This error should ideally be caught earlier, but double-check here
        ctx.log.error(
            f"[XSS Stored Inject] Invalid payload format received: '{payload_format}'. Skipping for {url}."
        )
        return

    ctx.log.debug(
        f"[XSS Stored Inject] Starting injection attempts for {url} (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        # Generate unique ID using the configured prefix
        probe_id = f"{probe_prefix}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
        try:
            unique_payload = payload_format.format(probe_id=probe_id)
        except KeyError:
            ctx.log.error(
                f"[XSS Stored Inject] Invalid format string '{payload_format}'. Skipping param {param_name}."
            )
            continue

        # Create copies and inject payload (appending is often better for stored checks)
        current_params = original_params.copy()
        current_data = original_data.copy()
        is_param_in_query = param_name in current_params
        original_value = (
            current_params.get(param_name)
            if is_param_in_query
            else current_data.get(param_name, "")
        )
        injected_value = original_value + unique_payload  # Append payload
        if is_param_in_query:
            current_params[param_name] = injected_value
        else:
            current_data[param_name] = injected_value

        payload_info = f"URL: {url}, Param: {param_name}, ProbeID: {probe_id}"

        # --- Prepare Filtered Headers ---
        request_headers = {
            k: v
            for k, v in original_headers.items()
            # Filter out headers that httpx should manage or that cause issues
            if k.lower() not in ["content-length", "host", "transfer-encoding"]
        }
        # Ensure Content-Type is preserved for POST/PUT etc. if it was urlencoded originally
        if method in ["POST", "PUT", "PATCH"] and "content-type" not in request_headers:
            original_content_type = original_headers.get("content-type")
            if (
                original_content_type and "urlencoded" in original_content_type
            ):  # Be specific for urlencoded
                request_headers["content-type"] = original_content_type
        # --- End Header Preparation ---

        try:
            # ctx.log.debug(f"[XSS Stored Inject] Sending probe '{probe_id}' to param '{param_name}'...") # Verbose
            # Send the request using the *filtered* headers
            response = await http_client.request(
                method,
                url.split("?")[0] if is_param_in_query else url,
                params=current_params if is_param_in_query else original_params,
                data=current_data if not is_param_in_query else original_data,
                headers=request_headers,  # <-- USE FILTERED HEADERS
                cookies=cookies,
            )
            # ctx.log.debug(f"[XSS Stored Inject] Received response (Status: {response.status_code})") # Verbose

            # --- Register the injection attempt via the addon instance ---
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": unique_payload,
                "probe_id": probe_id,
            }
            addon_instance.register_injection(probe_id, injection_details)

        except httpx.TimeoutException:
            ctx.log.warn(f"[XSS Stored Inject] Timeout sending probe: {payload_info}")
        except Exception as e:
            ctx.log.debug(
                f"[XSS Stored Inject] Exception during probe send/recv: {e} ({payload_info})"
            )


# End of nightcrawler/xss_scanner.py

