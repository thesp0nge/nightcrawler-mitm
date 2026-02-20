# nightcrawler/active_scans/idor_scanner.py
# Contains logic for basic IDOR active scanning.

import httpx
import difflib
from typing import Dict, Any, List, TYPE_CHECKING
from nightcrawler.active_scans.base import ActiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class IDORScanner(ActiveScanner):
    name: str = "IDOR"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """
        Attempts to detect Insecure Direct Object References (IDOR).
        """
        url, method = target_info["url"], target_info["method"].upper()
        original_params, original_data = target_info["params"], target_info["data"]
        original_headers = target_info["headers"]
        params_to_fuzz = list(original_params.keys()) + list(original_data.keys())

        if not params_to_fuzz:
            return

        self.logger.debug(f"[IDOR Scan] Starting for {url}")

        try:
            # Get the original response once
            original_response = await http_client.request(
                method, url, params=original_params, data=original_data, headers=original_headers,
            )
        except Exception as e:
            self.logger.debug(f"[IDOR Scan] Exception while getting original response for {url}: {e}")
            return

        for param_name in params_to_fuzz:
            is_param_in_query = param_name in original_params
            value = (original_params[param_name] if is_param_in_query else original_data[param_name])
            original_value = value[0] if isinstance(value, list) else value

            if original_value and original_value.isdigit():
                original_numeric_value = int(original_value)
                
                for offset in [-2, -1, 1, 2]:
                    fuzzed_value = str(original_numeric_value + offset)
                    current_params = original_params.copy()
                    current_data = original_data.copy()

                    if is_param_in_query: current_params[param_name] = fuzzed_value
                    else: current_data[param_name] = fuzzed_value
                    
                    try:
                        fuzzed_response = await http_client.request(
                            method, url.split("?")[0] if is_param_in_query else url,
                            params=current_params, data=current_data, headers=original_headers,
                        )

                        if (
                            original_response.status_code == fuzzed_response.status_code
                            and fuzzed_response.status_code == 200
                            and len(original_response.content) != len(fuzzed_response.content)
                        ):
                            # Dynamic Verification: Structure & Stability Check
                            try:
                                stability_check = await http_client.request(
                                    method, url, params=original_params, data=original_data, headers=original_headers
                                )
                                stability_ratio = difflib.SequenceMatcher(None, original_response.text, stability_check.text).ratio()
                                if stability_ratio < 0.98: continue

                                structure_ratio = difflib.SequenceMatcher(None, original_response.text, fuzzed_response.text).ratio()
                                
                                if 0.85 < structure_ratio < 0.999:
                                    payload_info_detail = (
                                        f"Param: {param_name}, Original: {original_value}, Fuzzed: {fuzzed_value}. "
                                        f"Similarity Ratio: {structure_ratio:.2f}"
                                    )
                                    payload_info_evidence = {
                                        "param": param_name,
                                        "original_value": original_value,
                                        "fuzzed_value": fuzzed_value,
                                        "similarity_ratio": structure_ratio,
                                    }
                                    self.addon_instance._log_finding(
                                        level="WARN",
                                        finding_type="IDOR Found? (Content Length Difference)",
                                        url=url,
                                        detail=payload_info_detail,
                                        evidence=payload_info_evidence,
                                        confidence="MEDIUM",
                                    )
                            except Exception: pass
                    except Exception as e:
                        self.logger.debug(f"[IDOR Scan] Exception: {e} ({param_name})")
