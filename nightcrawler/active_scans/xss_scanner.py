# nightcrawler/active_scans/xss_scanner.py
# Contains logic for basic Reflected XSS scanning and Stored XSS injection.

import httpx
import time
import random
import html
from typing import Dict, Any, List, TYPE_CHECKING
from bs4 import BeautifulSoup
from nightcrawler.active_scans.base import ActiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class XSSScanner(ActiveScanner):
    name: str = "XSS"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Orchestrates Reflected and Stored XSS scans."""
        # 1. Reflected XSS
        await self._scan_reflected(target_info, cookies, http_client)
        
        # 2. Stored XSS Injection
        await self._scan_stored_inject(target_info, cookies, http_client)

    async def _scan_reflected(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Attempts basic reflected XSS payloads."""
        payloads = self.addon_instance.xss_reflected_payloads
        if not payloads:
            return

        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
        request_url = url.split("?")[0]

        for param_name in params_to_fuzz:
            exact_finding_logged = False
            escaped_finding_logged = False
            for payload in payloads:
                if exact_finding_logged:
                    break

                current_params, current_data = original_params.copy(), original_data.copy()
                is_param_in_query = param_name in current_params

                value = (
                    current_params[param_name]
                    if is_param_in_query
                    else current_data[param_name]
                )
                original_value = value[0] if isinstance(value, list) else value
                original_value = original_value if original_value is not None else ""

                if self.addon_instance.smart_targeting and original_value and str(original_value).isdigit():
                    self.logger.debug(f"[XSS Smart Target] Skipping purely numeric param '{param_name}' for Reflected XSS.")
                    continue

                if is_param_in_query:
                    current_params[param_name] = payload
                else:
                    current_data[param_name] = payload

                payload_info_detail = f"Param: {param_name}, Payload Snippet: {payload[:50]}..."
                payload_info_evidence = {"param": param_name, "payload": payload[:100]}
                
                request_headers = {
                    k: v
                    for k, v in original_headers.items()
                    if k.lower() not in ["content-length", "host", "cookie"]
                }
                if cookies:
                    request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

                try:
                    response = await http_client.request(
                        method, request_url,
                        params=current_params, data=current_data, headers=request_headers,
                    )
                    if "html" in response.headers.get("Content-Type", "") and response.text:
                        if payload in response.text:
                            # Pre-existence Check
                            try:
                                orig_resp = await http_client.request(
                                    method, request_url, params=original_params, data=original_data, headers=request_headers
                                )
                                if payload in orig_resp.text: continue
                            except Exception: pass

                            # DOM-Aware Verification
                            verified_confidence = "MEDIUM"
                            canary_id = random.randint(1000, 9999)
                            tag_name = f"ncv{canary_id}"
                            canary_tag = f"<{tag_name}>"
                            
                            try:
                                v_params, v_data = original_params.copy(), original_data.copy()
                                if is_param_in_query: v_params[param_name] = canary_tag
                                else: v_data[param_name] = canary_tag
                                
                                v_resp = await http_client.request(
                                    method, request_url,
                                    params=v_params, data=v_data, headers=request_headers,
                                )
                                soup = BeautifulSoup(v_resp.text, "html.parser")
                                if soup.find(tag_name):
                                    verified_confidence = "HIGH"
                                elif payload.lower().startswith("javascript:"):
                                    is_executable_attr = False
                                    for attr_name in ["href", "src", "action", "formaction", "onclick", "onmouseover"]:
                                        if soup.find(attrs={attr_name: payload}):
                                            is_executable_attr = True
                                            break
                                    if is_executable_attr: verified_confidence = "HIGH"
                                    else: continue
                            except Exception: pass

                            if not exact_finding_logged:
                                self.addon_instance._log_finding(
                                    "ERROR", "XSS Found? (Reflected - Exact)", url,
                                    f"{payload_info_detail} (Reflection Verified: {verified_confidence})",
                                    payload_info_evidence, confidence=verified_confidence,
                                )
                                exact_finding_logged = True
                                break
                        elif not escaped_finding_logged:
                            payload_encoded = html.escape(payload, quote=True)
                            if payload != payload_encoded and payload_encoded in response.text:
                                self.addon_instance._log_finding(
                                    "INFO", "Passive Scan - Escaped Reflection Found", url,
                                    f"Input reflected but HTML-escaped. {payload_info_detail}",
                                    payload_info_evidence, confidence="LOW",
                                )
                                escaped_finding_logged = True
                except Exception as e:
                    self.logger.debug(f"[XSS Reflected Scan] Exception: {e} ({payload_info_detail})")

    async def _scan_stored_inject(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Injects unique, trackable payloads for Stored XSS checks."""
        probe_prefix = self.addon_instance.xss_stored_prefix
        payload_format = self.addon_instance.xss_stored_format
        if "{probe_id}" not in payload_format:
            return

        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())
        request_url = url.split("?")[0]

        for param_name in params_to_fuzz:
            probe_id = f"{probe_prefix}_{int(time.time())}_{random.randint(1000,9999)}_{param_name}"
            unique_payload = payload_format.format(probe_id=probe_id)
            current_params, current_data = original_params.copy(), original_data.copy()
            is_param_in_query = param_name in current_params

            value = (current_params[param_name] if is_param_in_query else current_data[param_name])
            original_value = value[0] if isinstance(value, list) else value
            original_value = original_value if original_value is not None else ""

            if self.addon_instance.smart_targeting and original_value and str(original_value).isdigit():
                self.logger.debug(f"[XSS Smart Target] Skipping numeric param '{param_name}' for Stored XSS injection.")
                continue

            injected_value = original_value + unique_payload
            if is_param_in_query: current_params[param_name] = injected_value
            else: current_data[param_name] = injected_value

            request_headers = {
                k: v for k, v in original_headers.items()
                if k.lower() not in ["content-length", "host", "cookie"]
            }
            if cookies:
                request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

            try:
                await http_client.request(
                    method, request_url,
                    params=current_params, data=current_data, headers=request_headers,
                )
                injection_details = {
                    "url": url, "param_name": param_name, "method": method,
                    "payload_used": injected_value, "probe_id": probe_id,
                }
                self.addon_instance.register_injection(probe_id, injection_details)
            except Exception as e:
                self.logger.debug(f"[XSS Stored Inject] Exception for ProbeID {probe_id}: {e}")
