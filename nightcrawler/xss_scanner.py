# nightcrawler/xss_scanner.py
import httpx
import time
import random
import html
import sys
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_xss_reflected_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Attempts basic reflected XSS payloads, logging ERROR for exact reflection
    and INFO for HTML-escaped reflection.
    """
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(f"[XSS Reflected Scan] Starting for {url}")
    for param_name in params_to_fuzz:
        exact_finding_logged = False
        escaped_finding_logged = False
        for payload in payloads:
            if exact_finding_logged:
                break

            current_params, current_data = original_params.copy(), original_data.copy()
            is_in_query = param_name in original_params
            if is_in_query:
                current_params[param_name] = payload
            else:
                current_data[param_name] = payload

            payload_detail = f"Param: {param_name}, Payload Snippet: {payload[:50]}..."
            payload_evidence = {"param": param_name, "payload": payload[:100]}

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
                    params=current_params if is_in_query else original_params,
                    data=current_data if not is_in_query else original_data,
                    headers=request_headers,
                )
                if "html" in response.headers.get("Content-Type", "") and response.text:
                    if payload in response.text:
                        if not exact_finding_logged:
                            addon_instance._log_finding(
                                "ERROR",
                                "XSS Found? (Reflected - Exact)",
                                url,
                                payload_detail,
                                payload_evidence,
                            )
                            exact_finding_logged = True
                            break
                    elif not escaped_finding_logged:
                        payload_encoded = html.escape(payload, quote=True)
                        if (
                            payload != payload_encoded
                            and payload_encoded in response.text
                        ):
                            addon_instance._log_finding(
                                "INFO",
                                "Passive Scan - Escaped Reflection Found",
                                url,
                                f"Input reflected but HTML-escaped. {payload_detail}",
                                payload_evidence,
                            )
                            escaped_finding_logged = True
            except Exception as e:
                logger.debug(f"[XSS Reflected Scan] Exception: {e} ({payload_detail})")


async def scan_xss_stored_inject(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    probe_prefix: str,
    payload_format: str,
    logger: Any,
):
    """Injects unique, trackable payloads for Stored XSS checks."""
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return
    if "{probe_id}" not in payload_format:
        logger.error(
            f"[XSS Stored Inject] Invalid format string '{payload_format}'. Skipping."
        )
        return

    logger.debug(f"[XSS Stored Inject] Starting attempts for {url}")
    for param_name in params_to_fuzz:
        probe_id = f"{probe_prefix}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
        unique_payload = payload_format.format(probe_id=probe_id)
        current_params, current_data = original_params.copy(), original_data.copy()
        is_in_query = param_name in original_params
        original_value = (
            current_params.get(param_name, "")
            if is_in_query
            else original_data.get(param_name, "")
        )
        injected_value = original_value + unique_payload
        if is_in_query:
            current_params[param_name] = injected_value
        else:
            current_data[param_name] = injected_value

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
            await http_client.request(
                method,
                url.split("?")[0] if is_in_query else url,
                params=current_params if is_in_query else original_params,
                data=current_data if not is_in_query else original_data,
                headers=request_headers,
            )
            injection_details = {
                "url": url,
                "param_name": param_name,
                "method": method,
                "payload_used": injected_value,
                "probe_id": probe_id,
            }
            addon_instance.register_injection(probe_id, injection_details)
        except Exception as e:
            logger.debug(f"[XSS Stored Inject] Exception for ProbeID {probe_id}: {e}")
