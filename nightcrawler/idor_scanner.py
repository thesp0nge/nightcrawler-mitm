# nightcrawler/idor_scanner.py
# Contains logic for basic IDOR active scanning.

import httpx
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_idor(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Attempts to detect Insecure Direct Object References (IDOR).
    It works by finding numeric parameters and trying to access adjacent resources.
    """
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return

    logger.debug(f"[IDOR Scan] Starting for {url}")

    try:
        # Get the original response once before looping through parameters
        original_response = await http_client.request(
            method,
            url,
            params=original_params,
            data=original_data,
            headers=original_headers,
        )
    except Exception as e:
        logger.debug(f"[IDOR Scan] Exception while getting original response for {url}: {e}")
        return

    for param_name in params_to_fuzz:
        is_param_in_query = param_name in original_params
        value = (
            original_params[param_name]
            if is_param_in_query
            else original_data[param_name]
        )
        original_value = value[0] if isinstance(value, list) else value

        if original_value and original_value.isdigit():
            original_numeric_value = int(original_value)
            
            # Test for IDOR by incrementing and decrementing the value
            for offset in [-2, -1, 1, 2]:
                fuzzed_value = str(original_numeric_value + offset)
                
                current_params = original_params.copy()
                current_data = original_data.copy()

                if is_param_in_query:
                    current_params[param_name] = fuzzed_value
                else:
                    current_data[param_name] = fuzzed_value
                
                try:
                    # Get the fuzzed response
                    fuzzed_response = await http_client.request(
                        method,
                        url.split("?")[0] if is_param_in_query else url,
                        params=current_params,
                        data=current_data,
                        headers=original_headers,
                    )

                    # Compare the responses
                    if (
                        original_response.status_code == fuzzed_response.status_code
                        and len(original_response.content) != len(fuzzed_response.content)
                        and fuzzed_response.status_code == 200
                    ):
                        payload_info_detail = f"Param: {param_name}, Original: {original_value}, Fuzzed: {fuzzed_value}"
                        payload_info_evidence = {
                            "param": param_name,
                            "original_value": original_value,
                            "fuzzed_value": fuzzed_value,
                            "original_len": len(original_response.content),
                            "fuzzed_len": len(fuzzed_response.content),
                        }
                        addon_instance._log_finding(
                            level="WARN",
                            finding_type="IDOR Found? (Content Length Difference)",
                            url=url,
                            detail=payload_info_detail,
                            evidence=payload_info_evidence,
                        )

                except Exception as e:
                    logger.debug(f"[IDOR Scan] Exception: {e} ({param_name})")
