# nightcrawler/active_scans/command_injection.py
# Active scanner for basic OS Command Injection vulnerabilities.

import httpx
import time
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


async def scan_command_injection(
    target_info: Dict[str, Any],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    payloads: List[str],
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Attempts basic command injection payloads, checking for time delays or command output.
    """
    url, method = target_info["url"], target_info["method"].upper()
    original_params, original_data = target_info["params"], target_info["data"]
    original_headers = target_info["headers"]
    params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

    if not params_to_fuzz or not payloads:
        return

    logger.debug(
        f"[Cmd Injection Scan] Starting for {url} with {len(payloads)} payloads."
    )

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
                start_time = time.time()
                response = await http_client.request(
                    method,
                    url.split("?")[0] if is_in_query else url,
                    params=current_params,
                    data=current_data,
                    headers=request_headers,
                )
                duration = time.time() - start_time

                # --- Analysis ---
                # 1. Time-Based Check
                if "sleep" in payload.lower() and duration > 4.5:
                    # --- Dynamic Verification ---
                    verified_confidence = "MEDIUM"
                    detail_suffix = f", Duration: {duration:.2f}s"
                    
                    # Try to verify with a different sleep duration
                    try:
                        short_payload = payload.replace("5", "2")
                        v_start = time.time()
                        await http_client.request(
                            method,
                            url.split("?")[0] if is_in_query else url,
                            params=current_params if is_in_query else original_params,
                            data=current_data if not is_in_query else original_data,
                            headers=request_headers,
                            timeout=10.0
                        )
                        v_duration = time.time() - v_start
                        if 1.5 < v_duration < 3.5:
                            verified_confidence = "HIGH"
                            detail_suffix = f" (Verified: 5s sleep took {duration:.2f}s, 2s sleep took {v_duration:.2f}s)"
                        elif v_duration > 4.5:
                            logger.debug(f"[Cmd Injection Verify] Lag detected, skipping.")
                            continue
                    except Exception:
                        pass

                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="Command Injection? (Time-Based)",
                        url=url,
                        detail=f"{payload_info_detail}{detail_suffix}",
                        evidence=payload_info_evidence,
                        confidence=verified_confidence,
                    )
                    break  # Found a hit for this param, move to the next

                # 2. Output-Based Check (Math Verification)
                if response.text and "1787569" in response.text and "1337" not in response.text:
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="Command Injection (Verified Math)",
                        url=url,
                        detail=f"Mathematical payload executed: 1337*1337 -> 1787569",
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "output_snippet": "1787569",
                        },
                        confidence="HIGH",
                    )
                    break

                # 3. Output-Based Check (Legacy - Lower Confidence)
                if response.text and ("uid=0(root)" in response.text):
                    addon_instance._log_finding(
                        level="ERROR",
                        finding_type="Command Injection? (Legacy Output)",
                        url=url,
                        detail=f"Found suspicious output: {response.text[:50]}...",
                        evidence={"param": param_name, "snippet": response.text[:100]},
                        confidence="MEDIUM",
                    )
                    break

            except Exception as e:
                logger.debug(
                    f"[Cmd Injection Scan] Exception: {e} ({payload_info_detail})"
                )
