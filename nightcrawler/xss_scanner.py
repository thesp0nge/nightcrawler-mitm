# nightcrawler/xss_scanner.py
# Contains logic for basic Reflected XSS scanning and Stored XSS injection.

import httpx
import time
import random
from mitmproxy import ctx
from typing import Dict, Any, List, TYPE_CHECKING

# Type hint for MainAddon to allow calling its methods like _log_finding, register_injection
# Avoids circular import error during static analysis.
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Reflected XSS Scan (Logs only first finding per parameter, includes header fix) ---


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
    Logs only the FIRST successful payload found for each parameter.
    Filters problematic headers before sending requests.
    """
    url = target_info["url"]
    method = target_info["method"].upper()
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

    # ctx.log.debug(f"[XSS Reflected Scan] Starting for {url}...") # Caller logs start of scans

    # Loop through each parameter identified in the original request
    for param_name in params_to_fuzz:
        # Flag to track if a finding has already been logged for this specific parameter
        finding_logged_for_this_param = False

        # ctx.log.debug(f"[XSS Reflected Scan] Fuzzing parameter: {param_name}") # Verbose

        # Loop through each payload for the current parameter
        for payload in payloads:
            # If we already found and logged a working payload for this parameter,
            # skip testing other payloads for it.
            if finding_logged_for_this_param:
                ctx.log.debug(
                    f"[XSS Reflected Scan] Finding already logged for param '{param_name}', skipping remaining payloads."
                )
                break  # Exit the inner payload loop

            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            # Inject payload (replacing original value for reflected)
            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            # Define details for logging BEFORE the try block
            payload_info_detail = (
                f"Param: {param_name}, Payload Snippet: {payload[:50]}..."
            )
            payload_info_evidence = {
                "param": param_name,
                "payload": payload[:100],
            }  # Truncate long payloads

            # --- Prepare Filtered Headers (Fix for Content-Length issue) ---
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
                if (
                    original_content_type
                    and "urlencoded" in original_content_type.lower()
                ):
                    request_headers["content-type"] = original_content_type
            # --- End Header Preparation ---

            try:
                # Send request using the FILTERED headers
                # ctx.log.debug(f"[XSS Reflected Scan] Sending payload '{payload[:20]}...'") # Verbose
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=request_headers,  # <-- Use the filtered headers
                    cookies=cookies,
                )
                # ctx.log.debug(f"[XSS Reflected Scan] Received response (Status: {response.status_code})") # Verbose

                # --- Basic Reflected XSS Response Analysis ---
                content_type = response.headers.get("Content-Type", "")
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text
                    except Exception:
                        pass

                    # Check for exact reflection
                    reflection_check_result = False
                    if response_text:
                        reflection_check_result = payload in response_text

                    # --- Log only if check passes AND not already logged for this param ---
                    if reflection_check_result and not finding_logged_for_this_param:
                        addon_instance._log_finding(  # Log via addon instance
                            level="ERROR",
                            finding_type="XSS Found? (Reflected)",
                            url=url,
                            detail=payload_info_detail,
                            evidence=payload_info_evidence,
                        )
                        # Set flag and break inner loop after first successful payload
                        finding_logged_for_this_param = True
                        break  # Stop testing other payloads for this parameter

            except httpx.TimeoutException:
                # Log timeout only if we haven't already found a vulnerability for this param
                if not finding_logged_for_this_param:
                    addon_instance._log_finding(
                        level="WARN",
                        finding_type="XSS Reflected Scan Timeout",
                        url=url,
                        detail=f"Timeout sending payload. {payload_info_detail}",
                        evidence=payload_info_evidence,
                    )
            except Exception as e:
                # Log other exceptions using ctx.log.debug
                ctx.log.debug(
                    f"[XSS Reflected Scan] Exception during payload send/recv: {e} ({payload_info_detail})"
                )

    # ctx.log.debug(f"[XSS Reflected Scan] Finished for {url}") # Caller logs overall finish


# --- Stored XSS Injection Attempt (Includes Header Fix) ---


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
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]  # Get original headers
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    # Validate format string contains the placeholder before starting loop
    if "{probe_id}" not in payload_format:
        ctx.log.error(
            f"[XSS Stored Inject] Invalid payload format received: '{payload_format}'. Skipping for {url}."
        )
        return

    # ctx.log.debug(f"[XSS Stored Inject] Starting attempts for {url}...") # Caller logs this

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

        # Create copies and inject payload (appending for stored checks)
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

        # Define details BEFORE try block for use in except block
        payload_info = f"URL: {url}, Param: {param_name}, ProbeID: {probe_id}"

        # --- Prepare Filtered Headers (Fix for Content-Length issue) ---
        request_headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in ["content-length", "host", "transfer-encoding"]
        }
        if method in ["POST", "PUT", "PATCH"] and "content-type" not in request_headers:
            original_content_type = original_headers.get("content-type")
            if original_content_type and (
                "urlencoded" in original_content_type.lower()
                or "json" in original_content_type.lower()
            ):  # Preserve common types
                request_headers["content-type"] = original_content_type
        # --- End Header Preparation ---

        try:
            # ctx.log.debug(f"[XSS Stored Inject] Sending probe '{probe_id}' to param '{param_name}'...") # Verbose
            # Send the request using the FILTERED headers
            response = await http_client.request(
                method,
                url.split("?")[0] if is_param_in_query else url,
                params=current_params if is_param_in_query else original_params,
                data=current_data if not is_param_in_query else original_data,
                headers=request_headers,  # <-- USE FILTERED HEADERS
                cookies=cookies,
            )
            # ctx.log.debug(f"[XSS Stored Inject] Received response (Status: {response.status_code})") # Verbose

            # --- Register the injection attempt ---
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": unique_payload,
                "probe_id": probe_id,
            }
            addon_instance.register_injection(probe_id, injection_details)

            # Optional: Add redirect URLs from response to revisit queue?
            # ... (logic for redirects can be added here if desired) ...

        except httpx.TimeoutException:
            ctx.log.warn(f"[XSS Stored Inject] Timeout sending probe: {payload_info}")
        except Exception as e:
            ctx.log.debug(
                f"[XSS Stored Inject] Exception during probe send/recv: {e} ({payload_info})"
            )

    # ctx.log.debug(f"[XSS Stored Inject] Finished attempts for {url}") # Caller logs finish


# End of nightcrawler/xss_scanner.py
