# nightcrawler/active_scans/sqli_scanner.py
# Contains logic for basic SQL Injection active scanning.

import httpx
import time
from typing import Dict, Any, List, TYPE_CHECKING
from nightcrawler.active_scans.base import ActiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class SQLiScanner(ActiveScanner):
    name: str = "SQL Injection"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Orchestrates SQLi scans."""
        payloads = self.addon_instance.sqli_payloads
        
        # 1. Basic Scan (Append mode)
        if payloads:
            await self._scan_basic(target_info, cookies, http_client, payloads, mode="append")
        
        # 2. Basic Scan (Replace mode)
        if payloads:
            await self._scan_basic(target_info, cookies, http_client, payloads, mode="replace")
        
        # 3. Boolean-based Blind Scan (Uses internal payloads)
        await self._scan_boolean_based(target_info, cookies, http_client)

    async def _scan_boolean_based(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Performs boolean-based blind SQLi checks."""
        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

        if not params_to_fuzz:
            return

        self.logger.debug(f"[SQLi Scan - Boolean] Starting for {url}")
        request_url = url.split("?")[0]

        # Define pairs of (true_payload, false_payload)
        boolean_payloads = [
            (" AND 1=1", " AND 1=0"),
            ("' AND '1'='1", "' AND '1'='0"),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"0"),
        ]

        for param_name in params_to_fuzz:
            for true_payload, false_payload in boolean_payloads:
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

                try:
                    # --- Send TRUE request ---
                    true_params = original_params.copy()
                    true_data = original_data.copy()
                    if is_param_in_query:
                        true_params[param_name] = original_value + true_payload
                    else:
                        true_data[param_name] = original_value + true_payload

                    true_response = await http_client.request(
                        method, request_url,
                        params=true_params, data=true_data, headers=original_headers,
                    )

                    # --- Send FALSE request ---
                    false_params = original_params.copy()
                    false_data = original_data.copy()
                    if is_param_in_query:
                        false_params[param_name] = original_value + false_payload
                    else:
                        false_data[param_name] = original_value + false_payload

                    false_response = await http_client.request(
                        method, request_url,
                        params=false_params, data=false_data, headers=original_headers,
                    )

                    # --- Compare responses ---
                    if (
                        true_response.status_code == false_response.status_code
                        and len(true_response.content) != len(false_response.content)
                    ):
                        # Simple stability check
                        stability_resp = await http_client.request(
                            method, request_url, params=original_params, data=original_data, headers=original_headers
                        )
                        stability_resp2 = await http_client.request(
                            method, request_url, params=original_params, data=original_data, headers=original_headers
                        )
                        if len(stability_resp.content) != len(stability_resp2.content):
                            self.logger.debug(f"[SQLi Verify] Skipping unstable page for {url}")
                            continue

                        payload_info_detail = f"Param: {param_name}, True: '{true_payload}', False: '{false_payload}'"
                        payload_info_evidence = {
                            "param": param_name,
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "true_len": len(true_response.content),
                            "false_len": len(false_response.content),
                        }
                        self.addon_instance._log_finding(
                            level="WARN",
                            finding_type="SQLi Found? (Boolean-Based Blind)",
                            url=url,
                            detail=payload_info_detail,
                            evidence=payload_info_evidence,
                            confidence="MEDIUM",
                        )
                except Exception as e:
                    self.logger.debug(f"[SQLi Scan - Boolean] Exception: {e} ({param_name})")

    async def _scan_basic(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
        payloads: List[str],
        mode: str = "append",
    ):
        """Attempts basic SQLi payloads."""
        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

        self.logger.debug(f"[SQLi Scan] Starting for {url} with {len(payloads)} payloads in '{mode}' mode.")
        request_url = url.split("?")[0]

        for param_name in params_to_fuzz:
            for payload in payloads:
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

                fuzzed_value = payload if mode == "replace" else original_value + payload

                if is_param_in_query:
                    current_params[param_name] = fuzzed_value
                else:
                    current_data[param_name] = fuzzed_value

                payload_info_detail = f"Param: {param_name}, Payload: {payload}, Mode: {mode}"
                payload_info_evidence = {"param": param_name, "payload": payload, "mode": mode}

                request_headers = {
                    k: v
                    for k, v in original_headers.items()
                    if k.lower() not in ["content-length", "host", "transfer-encoding", "connection", "cookie"]
                }
                if cookies:
                    request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

                try:
                    start_time = time.time()
                    response = await http_client.request(
                        method, request_url,
                        params=current_params, data=current_data, headers=request_headers,
                    )
                    duration = time.time() - start_time

                    error_patterns = ["sql syntax", "unclosed quotation", "odbc", "ora-", "invalid sql"]
                    response_text_lower = response.text.lower() if response.text else ""
                    if any(pattern in response_text_lower for pattern in error_patterns):
                        self.addon_instance._log_finding(
                            level="ERROR",
                            finding_type="SQLi Found? (Error-Based)",
                            url=url,
                            detail=payload_info_detail,
                            evidence=payload_info_evidence,
                            confidence="HIGH",
                        )
                    if "SLEEP" in payload.upper() and duration > 4.5:
                        # Dynamic Verification
                        short_payload = payload.replace("5", "2")
                        try:
                            v_start = time.time()
                            await http_client.request(
                                method, request_url,
                                params=current_params, data=current_data, headers=request_headers, timeout=10.0
                            )
                            v_duration = time.time() - v_start
                            if 1.5 < v_duration < 3.5:
                                confidence = "HIGH"
                                detail_suffix = f" (Verified: 5s payload took {duration:.2f}s, 2s payload took {v_duration:.2f}s)"
                            else:
                                if v_duration > 4.5: continue
                                confidence = "MEDIUM"
                                detail_suffix = f" (Time-based check, duration: {duration:.2f}s)"
                        except Exception:
                            confidence = "MEDIUM"
                            detail_suffix = f" (Time-based check, duration: {duration:.2f}s)"

                        self.addon_instance._log_finding(
                            level="ERROR",
                            finding_type="SQLi Found? (Time-Based)",
                            url=url,
                            detail=payload_info_detail + detail_suffix,
                            evidence=payload_info_evidence,
                            confidence=confidence,
                        )
                except Exception as e:
                    self.logger.debug(f"[SQLi Scan] Exception: {e} ({payload_info_detail})")
