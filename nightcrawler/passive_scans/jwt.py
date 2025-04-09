# nightcrawler/passive_scans/jwt.py
# Passive checks related to JSON Web Tokens (JWT).

import base64
import json
import datetime  # Keep for potential future use with timestamps if needed
from mitmproxy import http, ctx
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon


def check_request_for_jwt(request: http.Request, addon_instance: "MainAddon"):
    """Checks request headers (e.g., Authorization: Bearer) for JWTs."""
    auth_header = request.headers.get("Authorization")
    # Check specifically for Bearer token format
    if auth_header and auth_header.lower().startswith("bearer "):
        try:
            token = auth_header.split(None, 1)[1].strip()
            # Basic structural check: 3 parts separated by dots, minimum length
            if token and token.count(".") == 2 and len(token) > 20:
                _analyze_and_log_jwt(
                    token,
                    f"Request Header 'Authorization: Bearer' to {request.pretty_url}",
                    addon_instance,
                )
        except IndexError:
            # Header format was invalid (e.g., just "Bearer")
            pass
        except Exception as e:
            # Log unexpected errors during header processing
            ctx.log.debug(f"Error processing Authorization header for JWT check: {e}")


def check_response_for_jwt(
    response: http.Response, url: str, addon_instance: "MainAddon"
):
    """Checks response body (if JSON) and common headers for JWTs."""
    # Check common headers where JWTs might appear
    # Consider adding more headers if relevant (e.g., custom auth headers)
    for header_name in [
        "X-Auth-Token",
        "X-Access-Token",
        "Authentication-Info",
        "X-JWT-Assertion",
        "Id-Token",
    ]:
        header_value = response.headers.get(header_name)
        if header_value and header_value.count(".") == 2 and len(header_value) > 20:
            _analyze_and_log_jwt(
                header_value,
                f"Response Header '{header_name}' from {url}",
                addon_instance,
            )

    # Check response body if it appears to be JSON
    content_type = response.headers.get("Content-Type", "").lower()
    # Check if content exists and content-type indicates JSON
    if response.content and "application/json" in content_type:
        try:
            # Limit size of body parsed to avoid DoS on huge JSON responses
            max_body_size_for_json_parse = 1 * 1024 * 1024  # 1 MB limit
            if len(response.content) > max_body_size_for_json_parse:
                ctx.log.debug(
                    f"Response body from {url} too large ({len(response.content)} bytes) for JWT JSON parsing."
                )
                return

            # Use response.json() for safe decoding & parsing
            data = response.json()
            # Recursively search for potential JWTs within the parsed JSON data
            _find_jwt_in_data(data, f"Response Body from {url}", addon_instance)
        except (json.JSONDecodeError, ValueError):
            # Log if JSON parsing fails, might indicate malformed JSON
            ctx.log.debug(
                f"Could not parse JSON body from {url} while looking for JWTs."
            )
        except Exception as e:
            # Catch other potential errors during JSON processing
            ctx.log.warn(f"Error processing JSON body for JWTs from {url}: {e}")


def _find_jwt_in_data(
    data: Any, context: str, addon_instance: "MainAddon", max_depth=10
):
    """
    Recursively searches Python dicts and lists for strings that structurally resemble JWTs.
    Limits recursion depth to prevent stack overflows.
    """

    # Internal recursive helper function
    def _recursive_search(item: Any, current_depth: int):
        # Stop recursion if depth limit is reached
        if current_depth > max_depth:
            if current_depth == max_depth + 1:  # Log only once per branch
                ctx.log.debug(
                    f"Max recursion depth reached while searching for JWTs in {context}"
                )
            return

        if isinstance(item, dict):
            for key, value in item.items():
                # Define context for logging/reporting where the JWT was found
                current_context = f"{context} (key: '{key}')"
                # Check if the value itself is a potential JWT string
                if (
                    isinstance(value, str) and value.count(".") == 2 and len(value) > 20
                ):  # Basic check
                    _analyze_and_log_jwt(value, current_context, addon_instance)
                # Recurse into nested dictionaries or lists
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)
        elif isinstance(item, list):
            # Iterate through list items
            for i, value in enumerate(item):
                current_context = f"{context} (list index: {i})"
                # Check if the item itself is a potential JWT string
                if isinstance(value, str) and value.count(".") == 2 and len(value) > 20:
                    _analyze_and_log_jwt(value, current_context, addon_instance)
                # Recurse into nested dictionaries or lists
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)

    # Start the recursion with the initial data and depth 0
    _recursive_search(data, 0)


def _analyze_and_log_jwt(token: str, context: str, addon_instance: "MainAddon"):
    """
    Decodes JWT header and payload (without signature verification).
    Handles potential base64 padding issues and decoding errors.
    Logs findings using the addon's centralized logging method.
    """
    try:
        # Basic structural check again for safety
        parts = token.split(".")
        if len(parts) != 3:
            return

        header_b64, payload_b64, signature_b64 = parts

        # Helper function to decode base64url strings, handling potential padding errors
        def b64_decode(data: str) -> str:
            missing_padding = len(data) % 4
            if missing_padding:
                # Add required '=' padding
                data += "=" * (4 - missing_padding)
            # Decode using urlsafe base64, replacing errors in UTF-8 decoding
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

        # Decode header and payload JSON
        header = json.loads(b64_decode(header_b64))
        payload = json.loads(b64_decode(payload_b64))

        # Determine log level and finding type based on algorithm (e.g., warn for 'none')
        log_level = "INFO"  # Default level for finding a JWT
        finding_type = "Passive Scan - JWT Decoded"
        algo = header.get("alg", "N/A")  # Use get() for safety in case 'alg' is missing
        if isinstance(algo, str):  # Check type before upper()
            algo = algo.upper()
            if algo == "NONE":
                log_level = "ERROR"  # Algorithm 'none' is a security vulnerability
                finding_type = "Passive Scan - JWT Algorithm 'none' Detected!"
            elif (
                algo == "HS256" and len(signature_b64) < 10
            ):  # Very basic check for potentially weak HS256 secret
                log_level = "WARN"
                finding_type = "Passive Scan - JWT Potentially Weak HS256?"
        else:
            algo = "N/A"  # Handle non-string algo case

        # Prepare a preview of the payload, excluding potentially sensitive common keys
        excluded_keys = {
            "password",
            "secret",
            "key",
            "apikey",
            "access_token",
            "refresh_token",
            "client_secret",
            "pwd",
        }
        payload_preview = {
            k: (str(v)[:50] + "..." if isinstance(v, str) and len(str(v)) > 50 else v)
            for k, v in payload.items()
            if k.lower() not in excluded_keys
        }
        # Indicate if keys were excluded
        if len(payload) > len(payload_preview):
            payload_preview["..."] = "(some keys excluded)"

        # Log the finding using the centralized addon method
        addon_instance._log_finding(
            level=log_level,
            finding_type=finding_type,
            url=context,  # Use context string as the location info
            detail=f"JWT Decoded. Algo: {algo}, Type: {header.get('typ', 'N/A')}. Payload Keys: {list(payload.keys())}",
            evidence={
                "token_prefix": token[:10] + "...",  # Avoid logging full token
                "header": header,
                "payload_preview": payload_preview,
            },
        )

    except (TypeError, ValueError, base64.binascii.Error, json.JSONDecodeError) as e:
        # Log specifically if it looked like a JWT but failed standard decoding
        # Check structure again to reduce noise from random strings containing dots
        if token.count(".") == 2 and len(token) > 20:
            ctx.log.debug(
                f"[Passive Scan] Potential JWT found but failed decode: {token[:15]}... Error: {e}. Context: {context}"
            )
    except Exception as e:
        # Catch any other unexpected errors during analysis
        ctx.log.warn(
            f"[Passive Scan] Unexpected error analyzing potential JWT in {context}: {e}"
        )
