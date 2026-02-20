# nightcrawler/passive_scans/jwt.py
# Passive checks related to JSON Web Tokens (JWT).

import base64
import json
import datetime
import re
from mitmproxy import http
from typing import Any, Dict, TYPE_CHECKING
from nightcrawler.passive_scans.base import PassiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

JWT_STRUCTURE_REGEX = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")
POTENTIALLY_SENSITIVE_CLAIMS = {"email", "sub", "name", "groups", "roles", "permissions", "upn"}

def _b64_decode(data: str) -> str:
    missing_padding = len(data) % 4
    if missing_padding: data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

class JWTScanner(PassiveScanner):
    name: str = "JWT"

    async def scan_request(self, request: http.Request):
        """Checks request headers for JWTs."""
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            try:
                token = auth_header.split(None, 1)[1].strip()
                if token and JWT_STRUCTURE_REGEX.match(token):
                    self._analyze_and_log_jwt(token, f"Request Header 'Authorization: Bearer' to {request.pretty_url}")
            except Exception as e:
                self.logger.debug(f"Error processing Auth header for JWT: {e}")

    async def scan_response(self, response: http.Response, url: str):
        """Checks response body for JWTs."""
        if response.content and "application/json" in response.headers.get("Content-Type", "").lower():
            try:
                if len(response.content) > 1 * 1024 * 1024: return
                data = response.json()
                self._find_jwt_in_data(data, f"Response Body from {url}")
            except Exception as e:
                self.logger.warn(f"Error processing JSON body for JWTs from {url}: {e}")

    def _find_jwt_in_data(self, data: Any, context: str, max_depth=10):
        """Recursively searches for strings that structurally resemble JWTs."""
        def _recursive_search(item: Any, current_depth: int):
            if current_depth > max_depth: return
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                        self._analyze_and_log_jwt(value, f"{context} (key: '{key}')")
                    elif isinstance(value, (dict, list)):
                        _recursive_search(value, current_depth + 1)
            elif isinstance(item, list):
                for value in item:
                    if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                        self._analyze_and_log_jwt(value, f"{context} (in list)")
                    elif isinstance(value, (dict, list)):
                        _recursive_search(value, current_depth + 1)
        _recursive_search(data, 0)

    def _analyze_and_log_jwt(self, token: str, context: str):
        """Decodes JWT and checks for security issues."""
        try:
            parts = token.split(".")
            if len(parts) != 3: return
            header = json.loads(_b64_decode(parts[0]))
            payload = json.loads(_b64_decode(parts[1]))

            log_level = "INFO"
            finding_type = "Passive Scan - JWT Decoded"
            details = []
            evidence = {"header": header, "token_prefix": token[:15] + "..."}

            algo = header.get("alg", "N/A")
            if isinstance(algo, str) and algo.upper() == "NONE":
                log_level, finding_type = "ERROR", "Passive Scan - JWT Algorithm 'none' Detected!"
                details.append("Algorithm is 'none', which can bypass signature validation.")

            now_utc = datetime.datetime.now(datetime.timezone.utc)
            if "exp" in payload and isinstance(payload["exp"], (int, float)):
                exp_dt = datetime.datetime.fromtimestamp(payload["exp"], datetime.timezone.utc)
                if exp_dt < (now_utc - datetime.timedelta(minutes=1)):
                    log_level, details.append(f"Token is EXPIRED since {exp_dt.isoformat()}.")

            sensitive_keys_found = {k for k in payload.keys() if k.lower() in POTENTIALLY_SENSITIVE_CLAIMS}
            if sensitive_keys_found:
                details.append(f"Payload contains potentially sensitive keys: {sorted(list(sensitive_keys_found))}")
                if log_level == "INFO": finding_type = "Passive Scan - JWT with Sensitive Keys?"

            final_detail = f"Algo: {algo}. Issues: " + "; ".join(details) if details else f"Algo: {algo}."
            self.addon_instance._log_finding(log_level, finding_type, context, final_detail, evidence)
        except Exception as e:
            self.logger.debug(f"[Passive Scan] Error analyzing JWT in {context}: {e}")
