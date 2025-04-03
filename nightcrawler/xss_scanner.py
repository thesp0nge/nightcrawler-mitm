# nightcrawler/xss_scanner.py
# Contains logic for basic Reflected XSS scanning and Stored XSS injection.

import httpx
import time
import random
from mitmproxy import ctx
from typing import Dict, Any, List, TYPE_CHECKING

# Default payloads are now defined in addon.py and passed in.

# Type hint for MainAddon without causing circular import during type checking
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Reflected XSS Scan ---


async def scan_xss_reflected_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],  # Accept list of payloads as argument
):
    """
    Attempts basic reflected XSS payloads provided in the list by checking
    for immediate, exact reflection in the HTML response.
    Does NOT detect stored XSS.
    """
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    if not payloads:
        ctx.log.debug(
            f"[XSS Reflected Scan] No reflected XSS payloads provided for {url}"
        )
        return

    ctx.log.debug(
        f"[XSS Reflected Scan] Starting for {url} with {len(payloads)} payloads (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        # ctx.log.debug(f"[XSS Reflected Scan] Fuzzing parameter: {param_name}") # Verbose
        for payload in payloads:  # Iterate over passed payloads
            # Create copies and inject payload (replacing original value for reflected)
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params

            if is_param_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            payload_info = (
                f"URL: {url}, Param: {param_name}, Payload Snippet: {payload[:30]}..."
            )
            try:
                # ctx.log.debug(f"[XSS Reflected Scan] Sending payload '{payload[:20]}...'") # Verbose
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
                # ctx.log.debug(f"[XSS Reflected Scan] Received response (Status: {response.status_code})") # Verbose

                # --- Basic Reflected XSS Response Analysis (Exact Match) ---
                content_type = response.headers.get("Content-Type", "")
                # Only check HTML responses for exact payload reflection
                if "html" in content_type:
                    response_text = ""
                    try:
                        response_text = response.text  # Decode response body
                    except Exception:
                        pass  # Ignore decoding errors

                    # Check for exact, case-sensitive payload reflection. Very naive.
                    if response_text and payload in response_text:
                        ctx.log.error(f"[XSS FOUND? Reflected] {payload_info}")

            except httpx.TimeoutException:
                ctx.log.warn(
                    f"[XSS Reflected Scan] Timeout sending payload: {payload_info}"
                )
            except Exception as e:
                ctx.log.debug(
                    f"[XSS Reflected Scan] Exception during payload send/recv: {e} ({payload_info})"
                )

            # await asyncio.sleep(0.05) # Optional pause between payloads

    ctx.log.debug(f"[XSS Reflected Scan] Finished for {url}")


# --- Stored XSS Injection Attempt ---


async def scan_xss_stored_inject(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",  # Pass addon instance for state access (register_injection)
    probe_prefix: str,  # Pass configured prefix from options
    payload_format: str,  # Pass configured format string from options
):
    """
    Injects unique, trackable payloads into parameters using the provided prefix
    and format string, then registers the injection attempt with the main addon.
    It does NOT check the immediate response for reflection itself.
    """
    url = target_info["url"]
    method = target_info["method"]
    original_params = target_info["params"]
    original_data = target_info["data"]
    headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    # Validate format string contains the placeholder before starting loop
    if "{probe_id}" not in payload_format:
        ctx.log.error(
            f"[XSS Stored Inject] Invalid payload format configured: '{payload_format}'. Missing '{{probe_id}}'. Skipping stored injection for {url}."
        )
        return

    ctx.log.debug(
        f"[XSS Stored Inject] Starting injection attempts for {url} (Params: {params_to_fuzz})"
    )
    for param_name in params_to_fuzz:
        # Generate a unique payload ID for this specific injection point
        # Include timestamp, random element, and param name for uniqueness and context
        probe_id = f"{probe_prefix}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
        # Format the actual payload string using the template from config options
        try:
            unique_payload = payload_format.format(probe_id=probe_id)
        except KeyError:  # Handle potential errors if format string is malformed
            ctx.log.error(
                f"[XSS Stored Inject] Invalid payload format string: '{payload_format}'. Could not insert probe_id. Skipping param {param_name}."
            )
            continue  # Skip to next parameter

        # Create copies and inject payload (appending is often better for stored checks)
        current_params = original_params.copy()
        current_data = original_data.copy()
        is_param_in_query = param_name in current_params
        original_value = (
            current_params.get(param_name)
            if is_param_in_query
            else current_data.get(param_name, "")
        )

        # Inject by appending the unique payload to the original value
        injected_value = original_value + unique_payload
        if is_param_in_query:
            current_params[param_name] = injected_value
        else:
            current_data[param_name] = injected_value

        payload_info = (
            f"URL: {url}, Param: {param_name}, ProbeID: {probe_id}"  # For logging
        )
        try:
            ctx.log.debug(
                f"[XSS Stored Inject] Sending probe '{probe_id}' to param '{param_name}' for {url.split('?')[0]}"
            )
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
            # Log response status, but no reflection check here
            ctx.log.debug(
                f"[XSS Stored Inject] Received response for probe '{probe_id}' (Status: {response.status_code})"
            )

            # --- Register the injection attempt via the addon instance ---
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": unique_payload,  # Store the exact payload string injected
                "probe_id": probe_id,  # Store the unique ID for later lookup
            }
            # Call the registration method on the main addon instance passed as argument
            addon_instance.register_injection(probe_id, injection_details)

            # Optional: Add URLs from response (e.g., redirects) to revisit queue?
            # if response.is_redirect:
            #    redirect_url = urljoin(url, response.headers.get('Location'))
            #    if is_in_scope(redirect_url, addon_instance.effective_scope): # Check scope
            #         if redirect_url not in list(addon_instance.revisit_queue._queue): # Avoid rapid duplicates
            #             addon_instance.revisit_queue.put_nowait(redirect_url)
            #             ctx.log.debug(f"[Revisit Queue] Added redirect {redirect_url} after probe {probe_id}")

        except httpx.TimeoutException:
            ctx.log.warn(f"[XSS Stored Inject] Timeout sending probe: {payload_info}")
        except Exception as e:
            ctx.log.debug(
                f"[XSS Stored Inject] Exception during probe send/recv: {e} ({payload_info})"
            )

        # await asyncio.sleep(0.05) # Optional pause between parameter injections

    ctx.log.debug(f"[XSS Stored Inject] Finished injection attempts for {url}")
