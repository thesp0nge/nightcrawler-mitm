# nightcrawler/sqli_scanner.py
# Contains logic for basic SQL Injection active scanning.

import httpx
import time
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_sqli_boolean_based(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,
):
    """Performs boolean-based blind SQLi checks."""
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz:
        return

    logger.debug(f"[SQLi Scan - Boolean] Starting for {url}")

    # Define pairs of (true_payload, false_payload)
    boolean_payloads = [
        (" AND 1=1", " AND 1=0"),
        ("' AND '1'='1", "' AND '1'='0"),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"0"),
    ]

    for param_name in params_to_fuzz:
        for true_payload, false_payload in boolean_payloads:
            # --- Get original value ---
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params
            value = (
                current_params[param_name]
                if is_param_in_query
                else current_data[param_name]
            )
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""
            # --- End Get original value ---

            try:
                # --- Send TRUE request ---
                true_params = original_params.copy()
                true_data = original_data.copy()
                if is_param_in_query:
                    true_params[param_name] = original_value + true_payload
                else:
                    true_data[param_name] = original_value + true_payload

                true_response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=true_params,
                    data=true_data,
                    headers=original_headers,
                )

                # --- Send FALSE request ---
                false_params = original_params.copy()
                false_data = original_data.copy()
                if is_param_in_query:
                    false_params[param_name] = original_value + false_payload
                else:
                    false_data[param_name] = original_value + false_payload

                false_response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=false_params,
                    data=false_data,
                    headers=original_headers,
                )

                # --- Compare responses ---
                if (
                    true_response.status_code == false_response.status_code
                    and len(true_response.content) != len(false_response.content)
                ):
                    # --- Dynamic Verification: Stability Check ---
                    # Re-fetch original to see if length is stable or random
                    try:
                        stability_resp = await http_client.request(
                            method,
                            url,
                            params=original_params,
                            data=original_data,
                            headers=original_headers,
                        )
                        # If the length changed compared to original_response (implied by first call), it's unstable
                        # Since we don't have original_response content here easily, we compare with true/false
                        # Actually, better to just compare true with original. 
                        # If (original != true) AND (original != false) AND (true != false), 
                        # it might just be a random counter/timestamp in the page.
                        
                        # Let's do a simpler stability check: fetch original twice.
                        stability_resp2 = await http_client.request(
                            method,
                            url,
                            params=original_params,
                            data=original_data,
                            headers=original_headers,
                        )
                        if len(stability_resp.content) != len(stability_resp2.content):
                            logger.debug(f"[SQLi Verify] Skipping unstable page for {url}")
                            continue
                    except Exception:
                        pass

                    payload_info_detail = f"Param: {param_name}, True: '{true_payload}', False: '{false_payload}'"
                    payload_info_evidence = {
                        "param": param_name,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_len": len(true_response.content),
                        "false_len": len(false_response.content),
                    }
                    addon_instance._log_finding(
                        level="WARN",
                        finding_type="SQLi Found? (Boolean-Based Blind)",
                        url=url,
                        detail=payload_info_detail,
                        evidence=payload_info_evidence,
                        confidence="MEDIUM",
                    )
            except Exception as e:
                logger.debug(
                    f"[SQLi Scan - Boolean] Exception: {e} ({param_name})"
                )


async def scan_sqli_basic(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
    logger: Any,
    mode: str = "append",  # 'append' or 'replace'
):
    """Attempts basic SQLi payloads, logging findings via addon_instance."""
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(f"[SQLi Scan] Starting for {url} with {len(payloads)} payloads in '{mode}' mode.")

    for param_name in params_to_fuzz:
        for payload in payloads:
            current_params = original_params.copy()
            current_data = original_data.copy()
            is_param_in_query = param_name in current_params

            # --- CORRECTED LOGIC: Handle list values from parse_qs ---
            value = (
                current_params[param_name]
                if is_param_in_query
                else current_data[param_name]
            )
            # If the value is a list (from parse_qs), take the first element.
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""
            # --- END CORRECTION ---

            # --- Mode Logic ---
            if mode == "replace":
                fuzzed_value = payload
            else:  # append by default
                fuzzed_value = original_value + payload
            # --- End Mode Logic ---

            if is_param_in_query:
                current_params[param_name] = fuzzed_value
            else:
                current_data[param_name] = fuzzed_value

            payload_info_detail = f"Param: {param_name}, Payload: {payload}, Mode: {mode}"
            payload_info_evidence = {"param": param_name, "payload": payload, "mode": mode}

            request_headers = {
                k: v
                for k, v in original_headers.items()
                if k.lower()
                not in [
                    "content-length",
                    "host",
                    "transfer-encoding",
                    "connection",
                    "cookie",
                ]
            }
            if cookies:
                request_headers["Cookie"] = "; ".join(
                    [f"{k}={v}" for k, v in cookies.items()]
                )

            try:
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_param_in_query else url,
                    params=current_params,
                    data=current_data,
                    headers=request_headers,
                )
                duration = time.time() - start_time

                error_patterns = [
                    "sql syntax",
                    "unclosed quotation",
                    "odbc",
                    "ora-",
                    "invalid sql",
                ]
                response_text_lower = response.text.lower() if response.text else ""
                if any(pattern in response_text_lower for pattern in error_patterns):
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Error-Based)",
                        url=url,
                        detail=payload_info_detail,
                        evidence=payload_info_evidence,
                        confidence="HIGH",
                    )
                if "SLEEP" in payload.upper() and duration > 4.5:
                    # --- Dynamic Verification ---
                    # To filter out network lag, we try a shorter sleep
                    verified_confidence = "MEDIUM"
                    short_payload = payload.replace("5", "2")
                    
                    try:
                        short_params = current_params.copy()
                        short_data = current_data.copy()
                        if is_param_in_query:
                            short_params[param_name] = short_payload if mode == "replace" else original_value + short_payload
                        else:
                            short_data[param_name] = short_payload if mode == "replace" else original_value + short_payload
                        
                        v_start = time.time()
                        await http_client.request(
                            method,
                            url.split("?")[0] if is_param_in_query else url,
                            params=short_params,
                            data=short_data,
                            headers=request_headers,
                            timeout=10.0
                        )
                        v_duration = time.time() - v_start
                        
                        if 1.5 < v_duration < 3.5:
                            verified_confidence = "HIGH"
                            detail_suffix = f" (Verified: 5s payload took {duration:.2f}s, 2s payload took {v_duration:.2f}s)"
                        else:
                            # If the 2s sleep also took > 4.5s, it's probably network lag
                            if v_duration > 4.5:
                                logger.debug(f"[SQLi Verify] Potential False Positive (Lag): Both 5s and 2s payloads took >4.5s")
                                continue 
                            detail_suffix = f" (Time-based check, duration: {duration:.2f}s)"
                    except Exception:
                        detail_suffix = f" (Time-based check, duration: {duration:.2f}s)"

                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="SQLi Found? (Time-Based)",
                        url=url,
                        detail=payload_info_detail + detail_suffix,
                        evidence=payload_info_evidence,
                        confidence=verified_confidence,
                    )
            except Exception as e:
                logger.debug(f"[SQLi Scan] Exception: {e} ({payload_info_detail})")

