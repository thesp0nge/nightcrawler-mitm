# nightcrawler/xss_scanner.py
# Contains logic for basic Reflected XSS scanning and Stored XSS injection.

import httpx
import time
import random
import html  # Needed for escaped check
import sys  # Needed for fallback print
from mitmproxy import ctx  # Used for debug logs, safe in real execution
from typing import Dict, Any, List, TYPE_CHECKING

# Type hint for MainAddon
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Reflected XSS Scan (Includes fixes for header, single log, escaped log) ---


async def scan_xss_reflected_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
):
    """
    Attempts basic reflected XSS payloads provided in the list.
    Logs ERROR for exact reflection (first payload hit per param).
    Logs INFO for HTML-escaped reflection (if no exact reflection found for param).
    Filters problematic headers before sending requests.
    """
    url = target_info["url"]
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    if not payloads:
        # Use ctx safely here as it's called within mitmproxy's async context
        try:
            ctx.log.debug(
                f"[XSS Reflected Scan] No reflected XSS payloads provided for {url}"
            )
        except Exception:
            pass  # Ignore if ctx not available (e.g., theoretical direct call)
        return

    # ctx.log.debug(f"[XSS Reflected Scan] Starting for {url}...") # Caller logs this

    # Loop through each parameter identified in the original request
    for param_name in params_to_fuzz:
        exact_finding_logged_for_this_param = False
        escaped_finding_logged_for_this_param = False  # Track info logs for this param

        # ctx.log.debug(f"[XSS Reflected Scan] Fuzzing parameter: {param_name}") # Verbose

        # Loop through each payload for the current parameter
        for payload in payloads:
            # If we already found an exact reflection for this param, stop testing it
            if exact_finding_logged_for_this_param:
                break  # Exit the inner payload loop

            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
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
                if k.lower()
                not in [
                    "content-length",
                    "host",
                    "transfer-encoding",
                    "connection",
                ]  # Added connection
            }
            # Ensure Content-Type is preserved for relevant POST methods
            if method == "POST" and "content-type" not in request_headers:
                original_content_type = original_headers.get("content-type")
                if (
                    original_content_type
                    and "urlencoded" in original_content_type.lower()
                ):
                    request_headers["content-type"] = original_content_type
            # --- End Header Preparation ---
            if cookies:
                cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                request_headers["Cookie"] = cookie_string

            try:
                # Send request using the FILTERED headers
                # ctx.log.debug(f"[XSS Reflected Scan] Sending payload '{payload[:20]}...' to param '{param_name}'") # Verbose
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params if is_param_in_query else original_params,
                    data=current_data if not is_param_in_query else original_data,
                    headers=request_headers,  # <-- Use the filtered headers
                )
                # ctx.log.debug(f"[XSS Reflected Scan] Received response (Status: {response.status_code})") # Verbose

                content_type = response.headers.get("Content-Type", "")
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text
                    except Exception:
                        pass  # Ignore decoding errors

                    if response_text:
                        # --- Differentiated Logging Logic ---
                        # 1. Check for EXACT reflection first
                        exact_match = payload in response_text
                        if exact_match:
                            # Log as ERROR only once for this parameter
                            if not exact_finding_logged_for_this_param:
                                addon_instance._log_finding(
                                    level="ERROR",
                                    finding_type="XSS Found? (Reflected - Exact)",
                                    url=url,
                                    detail=payload_info_detail,
                                    evidence=payload_info_evidence,
                                )
                                exact_finding_logged_for_this_param = True
                                break  # Stop testing other payloads for this parameter

                        # 2. If no exact match found yet, check for ESCAPED reflection
                        # Log INFO only once per parameter for escaped reflection to reduce noise
                        elif (
                            not exact_finding_logged_for_this_param
                            and not escaped_finding_logged_for_this_param
                        ):
                            try:
                                # Escape the payload using standard HTML escaping
                                payload_encoded = html.escape(payload, quote=True)
                                # Check if encoding happened AND the escaped string is present
                                if (
                                    payload != payload_encoded
                                    and payload_encoded in response_text
                                ):
                                    addon_instance._log_finding(
                                        level="INFO",  # Log as INFO, not ERROR
                                        finding_type="Passive Scan - Escaped Reflection Found",
                                        url=url,
                                        detail=f"Input reflected but HTML-escaped. {payload_info_detail}",
                                        evidence=payload_info_evidence,  # Still useful to know which payload/param
                                    )
                                    # Mark that we found an escaped reflection for this parameter
                                    escaped_finding_logged_for_this_param = True
                                    # DO NOT break here, continue checking other payloads in case one reflects exactly
                            except Exception as e_escape:
                                # Use ctx safely here
                                try:
                                    ctx.log.debug(
                                        f"Error during html.escape check: {e_escape}"
                                    )
                                except Exception:
                                    pass  # Ignore if ctx not available
                        # --- End Differentiated Logic ---

            except httpx.TimeoutException:
                # Log timeout only if we haven't already found an exact vulnerability for this param
                if not exact_finding_logged_for_this_param:
                    addon_instance._log_finding(
                        level="WARN",
                        finding_type="XSS Reflected Scan Timeout",
                        url=url,
                        detail=f"Timeout sending payload. {payload_info_detail}",
                        evidence=payload_info_evidence,
                    )
            except Exception as e:
                # Use ctx safely here for debug logging
                try:
                    ctx.log.debug(
                        f"[XSS Reflected Scan] Exception during payload send/recv: {e} ({payload_info_detail})"
                    )
                except Exception:  # Fallback print if ctx fails
                    print(
                        f"[DEBUG][XSS Reflected Scan] Exception: {e} ({payload_info_detail})",
                        file=sys.stderr,
                    )

    # ctx.log.debug(f"[XSS Reflected Scan] Finished for {url}") # Caller logs overall finish


# --- Stored XSS Injection Attempt (Includes Header Fix, payload_used Fix, ctx.log fix) ---


async def scan_xss_stored_inject(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",  # Pass addon instance for state access
    probe_prefix: str,  # Pass configured prefix
    payload_format: str,  # Pass configured format string
):
    """
    Injects unique, trackable payloads using the provided prefix
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
        # Cannot use ctx.log here safely during pytest runs. Use print or standard logging.
        # Logging as an error might be too strong if it's just skipping.
        # Use print stderr for visibility during tests or problematic runs.
        print(
            f"[XSS Stored Inject] ERROR: Invalid format string '{payload_format}'. Missing '{{probe_id}}'. Skipping for {url}.",
            file=sys.stderr,
        )
        return  # Exit early

    # ctx.log.debug(f"[XSS Stored Inject] Starting attempts for {url}...") # Caller logs this

    for param_name in params_to_fuzz:
        # Generate unique ID
        probe_id = f"{probe_prefix}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
        try:
            unique_payload = payload_format.format(probe_id=probe_id)
        except KeyError:
            # Cannot use ctx.log safely here either
            print(
                f"[XSS Stored Inject] ERROR: Invalid format string '{payload_format}'. Skipping param {param_name}.",
                file=sys.stderr,
            )
            continue  # Skip to next parameter

        # Create copies and inject payload (appending for stored checks)
        current_params = original_params.copy()
        current_data = original_data.copy()
        is_param_in_query = param_name in current_params
        original_value = (
            current_params.get(param_name)
            if is_param_in_query
            else current_data.get(param_name, "")
        )
        # Value actually injected (original + probe)
        injected_value = original_value + unique_payload
        if is_param_in_query:
            current_params[param_name] = injected_value
        else:
            current_data[param_name] = injected_value

        # Define details BEFORE try block for use in except block
        payload_info = f"URL: {url}, Param: {param_name}, ProbeID: {probe_id}"

        # --- Prepare Filtered Headers ---
        request_headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower()
            not in ["content-length", "host", "transfer-encoding", "connection"]
        }
        if method in ["POST", "PUT", "PATCH"] and "content-type" not in request_headers:
            original_content_type = original_headers.get("content-type")
            if original_content_type and (
                "urlencoded" in original_content_type.lower()
                or "json" in original_content_type.lower()
            ):
                request_headers["content-type"] = original_content_type
        # --- End Header Preparation ---
        if cookies:
            cookie_string = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            request_headers["Cookie"] = cookie_string

        try:
            # ctx.log.debug(f"[XSS Stored Inject] Sending probe '{probe_id}' to param '{param_name}'...") # Verbose
            # Send the request using the FILTERED headers
            response = await http_client.request(
                method,
                url.split("?")[0] if is_param_in_query else url,
                params=current_params if is_param_in_query else original_params,
                data=current_data if not is_param_in_query else original_data,
                headers=request_headers,
            )
            # ctx.log.debug(f"[XSS Stored Inject] Received response (Status: {response.status_code})") # Verbose

            # --- Register the injection attempt ---
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": injected_value,
                "probe_id": probe_id,
            }
            # Call the registration method on the main addon instance passed as argument
            addon_instance.register_injection(probe_id, injection_details)

        except httpx.TimeoutException:
            # Use ctx safely here (called within addon context eventually)
            try:
                ctx.log.warn(
                    f"[XSS Stored Inject] Timeout sending probe: {payload_info}"
                )
            except Exception:
                pass
        except Exception as e:
            try:
                ctx.log.debug(
                    f"[XSS Stored Inject] Exception during probe send/recv: {e} ({payload_info})"
                )
            except Exception:
                pass

    # ctx.log.debug(f"[XSS Stored Inject] Finished attempts for {url}") # Caller logs finish


# End of nightcrawler/xss_scanner.py
