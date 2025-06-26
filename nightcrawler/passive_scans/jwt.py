# nightcrawler/passive_scans/jwt.py
# Passive checks related to JSON Web Tokens (JWT).

import base64
import json
import datetime
import re
from mitmproxy import http
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# Regex to check the basic structure of a JWT (3 Base64URL parts separated by dots)
JWT_STRUCTURE_REGEX = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")
POTENTIALLY_SENSITIVE_CLAIMS = {
    "email",
    "sub",
    "name",
    "groups",
    "roles",
    "permissions",
    "upn",
}


def _b64_decode(data: str) -> str:
    """Safely decodes base64url strings, handling padding and UTF-8 errors."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")


def check_request_for_jwt(
    request: http.Request, addon_instance: "MainAddon", logger: Any
):
    """Checks request headers (Authorization: Bearer) for JWTs."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        try:
            token = auth_header.split(None, 1)[1].strip()
            if token and JWT_STRUCTURE_REGEX.match(token):
                _analyze_and_log_jwt(
                    token,
                    f"Request Header 'Authorization: Bearer' to {request.pretty_url}",
                    addon_instance,
                    logger,
                )
        except Exception as e:
            logger.debug(f"Error processing Auth header for JWT: {e}")


def check_response_for_jwt(
    response: http.Response, url: str, addon_instance: "MainAddon", logger: Any
):
    """Checks response body (if JSON) and common headers for JWTs."""
    if (
        response.content
        and "application/json" in response.headers.get("Content-Type", "").lower()
    ):
        try:
            if len(response.content) > 1 * 1024 * 1024:
                return
            data = response.json()
            _find_jwt_in_data(data, f"Response Body from {url}", addon_instance, logger)
        except Exception as e:
            logger.warn(f"Error processing JSON body for JWTs from {url}: {e}")


def _find_jwt_in_data(
    data: Any, context: str, addon_instance: "MainAddon", logger: Any, max_depth=10
):
    """Recursively searches for strings that structurally resemble JWTs."""

    def _recursive_search(item: Any, current_depth: int):
        if current_depth > max_depth:
            return
        if isinstance(item, dict):
            for key, value in item.items():
                if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                    _analyze_and_log_jwt(
                        value, f"{context} (key: '{key}')", addon_instance, logger
                    )
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)
        elif isinstance(item, list):
            for value in item:
                if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                    _analyze_and_log_jwt(
                        value, f"{context} (in list)", addon_instance, logger
                    )
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)

    _recursive_search(data, 0)


def _analyze_and_log_jwt(
    token: str, context: str, addon_instance: "MainAddon", logger: Any
):
    """Decodes JWT and checks for common security issues."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return

        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))

        # --- If decoding is successful, proceed with analysis ---
        log_level = "INFO"
        finding_type = "Passive Scan - JWT Decoded"
        details = []
        evidence = {"header": header, "token_prefix": token[:15] + "..."}

        # Analyze Algorithm
        algo = header.get("alg", "N/A")
        if isinstance(algo, str) and algo.upper() == "NONE":
            log_level = "ERROR"
            finding_type = "Passive Scan - JWT Algorithm 'none' Detected!"
            details.append(
                "Algorithm is 'none', which can bypass signature validation."
            )

        # Analyze Timestamps
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        time_buffer = datetime.timedelta(minutes=1)

        if "exp" in payload and isinstance(payload["exp"], (int, float)):
            exp_dt = datetime.datetime.fromtimestamp(
                payload["exp"], datetime.timezone.utc
            )
            if exp_dt < (now_utc - time_buffer):
                log_level = "WARN"
                details.append(f"Token is EXPIRED since {exp_dt.isoformat()}.")

        # Identify Sensitive Keys
        sensitive_keys_found = {
            k for k in payload.keys() if k.lower() in POTENTIALLY_SENSITIVE_CLAIMS
        }
        if sensitive_keys_found:
            details.append(
                f"Payload contains potentially sensitive keys: {sorted(list(sensitive_keys_found))}"
            )
            if log_level == "INFO":
                finding_type = "Passive Scan - JWT with Sensitive Keys?"

        # Consolidate details for logging
        final_detail = f"Algo: {algo}."
        if details:
            final_detail += " Issues: " + "; ".join(details)

        addon_instance._log_finding(
            log_level, finding_type, context, final_detail, evidence
        )

    except (TypeError, ValueError, base64.binascii.Error, json.JSONDecodeError) as e:
        # This block now ONLY handles decoding/parsing errors and does not depend on other variables.
        logger.debug(
            f"[Passive Scan] Potential JWT found but failed to decode/parse: {token[:15]}... Error: {e}. Context: {context}"
        )
    except Exception as e:
        logger.warn(
            f"[Passive Scan] Unexpected error analyzing potential JWT in {context}: {e}"
        )


# End of nightcrawler/passive_scans/jwt.py
