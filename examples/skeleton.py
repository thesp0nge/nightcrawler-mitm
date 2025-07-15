i  # nightcrawler/active_scans/skeleton.py
# A skeleton template for creating new active scanners for Nightcrawler.
#
# To create a new scanner:
# 1. Copy this file and rename it (e.g., my_scanner.py).
# 2. Define your payloads and logic inside the scan function.
# 3. Import and call your new scan function from the _scan_worker in addon.py.
# 4. Add new options to addon.py if your scanner needs them.
# 5. Create a new test file in tests/ to verify your scanner's logic.

import httpx
from typing import Dict, Any, List, TYPE_CHECKING

# It's good practice to use TYPE_CHECKING to import MainAddon for type hints.
# This avoids circular import errors at runtime.
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Define Your Payloads and Configuration Here ---
# Give your payloads descriptive names.
SKELETON_SCANNER_PAYLOADS: List[str] = [
    "payload1",
    "payload2",
    # ...add more payloads...
]


# --- The Scanner Function ---
# All active scanner functions should follow this signature.
async def scan_skeleton_vulnerability(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Checks for a custom vulnerability by sending modified requests.

    Args:
        target_info (dict): A dictionary containing details of the original request
                            (url, method, params, data, headers).
        cookies (dict): Cookies from the original request.
        http_client (httpx.AsyncClient): The shared, configured httpx client for making requests.
        addon_instance (MainAddon): The instance of the main addon, used to call _log_finding.
        logger (Any): The logger instance (ctx.log) for printing debug/error messages.
    """
    # Extract details from the original request
    url = target_info["url"]
    method = target_info["method"].upper()
    original_params = target_info["params"]
    original_data = target_info["data"]
    original_headers = target_info["headers"]

    # Decide which parameters to test. You can check all of them, or look for specific names.
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
    if not params_to_fuzz:
        return  # Exit if there are no parameters to test

    logger.debug(
        f"[Skeleton Scan] Starting for {url}. Params to test: {params_to_fuzz}"
    )

    # Prepare headers for your requests (filtering out problematic ones)
    request_headers = {
        k: v
        for k, v in original_headers.items()
        if k.lower() not in ["content-length", "host", "cookie"]
    }
    if cookies:
        request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

    # Loop through each parameter and payload
    for param_name in params_to_fuzz:
        for payload in SKELETON_SCANNER_PAYLOADS:
            # Create copies of the original request data to modify
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_in_query = param_name in original_params

            # Inject your payload into the correct part of the request
            if is_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            try:
                # Send the modified request
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_in_query else url,
                    params=current_params,
                    data=current_data,
                    headers=request_headers,
                )

                # --- Analyze the Response ---
                # This is where your custom logic goes.
                # Check the status code, headers, or response body for signs of a vulnerability.
                # For example, let's say we found a vulnerability if the response contains "VulnerablePattern".
                if response.text and "VulnerablePattern" in response.text:
                    # If found, log it using the addon's centralized logger.
                    # This ensures it appears in the console, JSONL, and HTML report.
                    addon_instance._log_finding(
                        level="ERROR",  # Or "WARN" or "INFO"
                        finding_type="Skeleton Vulnerability Found",
                        url=url,
                        detail=f"The application responded with a vulnerable pattern for payload '{payload}' in parameter '{param_name}'.",
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "response_snippet": response.text[:100],
                        },
                    )
                    # Optional: break if you only want to report one finding per parameter
                    break

            except Exception as e:
                logger.debug(
                    f"[Skeleton Scan] Exception for Param: {param_name}, Payload: {payload}: {e}"
                )

    logger.debug(f"[Skeleton Scan] Finished for {url}")
