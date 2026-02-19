# nightcrawler/active_scans/template_injection.py
# Active scanner for basic Server-Side Template Injection (SSTI) vulnerabilities.

import httpx
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_template_injection(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Attempts basic SSTI payloads by checking for mathematical evaluation in the response.
    """
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(f"[SSTI Scan] Starting for {url} with {len(payloads)} payloads.")

    for param_name in params_to_fuzz:
        for payload in payloads:
            current_params, current_data = original_params.copy(), original_data.copy()
            is_in_query = param_name in original_params

            value = (
                current_params.get(param_name)
                if is_in_query
                else current_data.get(param_name)
            )
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""

            injected_value = original_value + payload
            if is_in_query:
                current_params[param_name] = injected_value
            else:
                current_data[param_name] = injected_value

            payload_info_detail = f"Param: {param_name}, Payload: {payload}"
            payload_info_evidence = {"param": param_name, "payload": payload}

            request_headers = {
                k: v
                for k, v in original_headers.items()
                if k.lower() not in ["content-length", "host", "cookie"]
            }
            if cookies:
                request_headers["Cookie"] = "; ".join(
                    [f"{k}={v}" for k, v in cookies.items()]
                )

            try:
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_in_query else url,
                    params=current_params,
                    data=current_data,
                    headers=request_headers,
                )

                # --- Analysis ---
                # Check if the response contains the result of 1337*1337 (1787569), but not the original payload
                if (
                    response.text
                    and "1787569" in response.text
                    and payload not in response.text
                ):
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="Server-Side Template Injection? (SSTI)",
                        url=url,
                        detail=f"Payload '{payload}' was evaluated to '1787569'.",
                        evidence=payload_info_evidence,
                        confidence="HIGH",
                    )
                    # Break after first hit for this parameter to reduce noise
                    break

            except Exception as e:
                logger.debug(f"[SSTI Scan] Exception: {e} ({payload_info_detail})")
