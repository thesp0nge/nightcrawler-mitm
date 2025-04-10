# nightcrawler/passive_scans/jwt.py
# Passive checks related to JSON Web Tokens (JWT).

import base64
import json
import datetime  # Added for timestamp comparisons
import re  # Added for improved JWT detection regex
from mitmproxy import http, ctx
from typing import Any, Dict, Optional, TYPE_CHECKING, Union  # Added Union

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Regex to check the basic structure of a JWT (3 Base64URL parts separated by dots)
# Allows for empty signature part, as it might not always be present or relevant for checks.
# Checks for valid Base64URL characters (A-Z, a-z, 0-9, -, _)
JWT_STRUCTURE_REGEX = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")

# Common potentially sensitive claim keys to look for
POTENTIALLY_SENSITIVE_CLAIMS = {
    "email",
    "sub",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "phone_number",
    "address",
    "birthdate",
    "groups",
    "roles",
    "permissions",
    "upn",
    "oid",
    "unique_name",
    "nonce",
    "jti",
    "sid",  # Include IDs as potentially correlatable
}


# Helper function to decode base64url strings, handling padding issues
def _b64_decode(data: str) -> str:
    """Safely decodes base64url strings, handling padding and UTF-8 errors."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    # Use errors='replace' to handle potential invalid UTF-8 sequences
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except (TypeError, base64.binascii.Error):
        # Re-raise specific errors if needed, or handle them
        raise ValueError("Invalid base64 string")


def check_request_for_jwt(request: http.Request, addon_instance: "MainAddon"):
    """Checks request headers (e.g., Authorization: Bearer) for JWTs."""
    auth_header = request.headers.get("Authorization")
    # Check specifically for Bearer token format
    if auth_header and auth_header.lower().startswith("bearer "):
        try:
            token = auth_header.split(None, 1)[1].strip()
            # Use regex for better structural check than just counting dots
            if token and JWT_STRUCTURE_REGEX.match(token):
                _analyze_and_log_jwt(
                    token,
                    f"Request Header 'Authorization: Bearer' to {request.pretty_url}",
                    addon_instance,
                )
        except IndexError:
            pass  # Header format invalid
        except Exception as e:
            ctx.log.debug(f"Error processing Authorization header for JWT check: {e}")


def check_response_for_jwt(
    response: http.Response, url: str, addon_instance: "MainAddon"
):
    """Checks response body (if JSON) and common headers for JWTs."""
    # Check common headers where JWTs might appear
    for header_name in [
        "X-Auth-Token",
        "X-Access-Token",
        "Authentication-Info",
        "X-JWT-Assertion",
        "Id-Token",
    ]:
        header_value = response.headers.get(header_name)
        if header_value and JWT_STRUCTURE_REGEX.match(header_value):
            _analyze_and_log_jwt(
                header_value,
                f"Response Header '{header_name}' from {url}",
                addon_instance,
            )

    # Check response body if it appears to be JSON
    content_type = response.headers.get("Content-Type", "").lower()
    if response.content and "application/json" in content_type:
        try:
            max_body_size = 1 * 1024 * 1024  # 1MB limit
            if len(response.content) > max_body_size:
                ctx.log.debug(
                    f"Response body from {url} too large ({len(response.content)}) for JWT JSON parsing."
                )
                return
            data = response.json()  # Use built-in JSON parsing
            _find_jwt_in_data(data, f"Response Body from {url}", addon_instance)
        except (json.JSONDecodeError, ValueError):
            ctx.log.debug(f"Could not parse JSON from {url} for JWTs.")
        except Exception as e:
            ctx.log.warn(f"Error processing JSON body for JWTs from {url}: {e}")


def _find_jwt_in_data(
    data: Any, context: str, addon_instance: "MainAddon", max_depth=10
):
    """Recursively searches Python dicts and lists for strings that structurally resemble JWTs."""

    def _recursive_search(item: Any, current_depth: int):
        if current_depth > max_depth:
            if current_depth == max_depth + 1:
                ctx.log.debug(
                    f"Max recursion depth reached searching JWTs in {context}"
                )
            return

        if isinstance(item, dict):
            for key, value in item.items():
                current_context = f"{context} (key: '{key}')"
                if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                    _analyze_and_log_jwt(value, current_context, addon_instance)
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)
        elif isinstance(item, list):
            for i, value in enumerate(item):
                current_context = f"{context} (list index: {i})"
                if isinstance(value, str) and JWT_STRUCTURE_REGEX.match(value):
                    _analyze_and_log_jwt(value, current_context, addon_instance)
                elif isinstance(value, (dict, list)):
                    _recursive_search(value, current_depth + 1)

    _recursive_search(data, 0)


def _analyze_and_log_jwt(token: str, context: str, addon_instance: "MainAddon"):
    """
    Decodes JWT header and payload (no signature verification).
    Checks standard claims like exp, nbf, iat.
    Identifies potentially sensitive claims.
    Logs findings using the addon's centralized logger.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return  # Should be caught by regex, but double-check

        header_b64, payload_b64, signature_b64 = parts

        header = json.loads(_b64_decode(header_b64))
        payload = json.loads(_b64_decode(payload_b64))

        # --- Initialize Finding Details ---
        log_level = "INFO"  # Default level
        finding_type = "Passive Scan - JWT Decoded"
        details = []  # List to collect issues found
        evidence = {
            "token_prefix": token[:10] + "...",  # Avoid logging full token
            "header": header,
            "payload_preview": {},  # Filled later
        }

        # --- Analyze Header ---
        algo = header.get("alg", "N/A")
        if isinstance(algo, str):
            algo = algo.upper()
            if algo == "NONE":
                log_level = "ERROR"
                finding_type = "Passive Scan - JWT Algorithm 'none' Detected!"
                details.append(
                    "Algorithm is 'none'! Signature validation likely bypassed."
                )
            elif (
                algo == "HS256" and not signature_b64
            ):  # Basic check for missing signature with symmetric alg
                log_level = "WARN"
                finding_type = "Passive Scan - JWT Potentially Weak HS256"
                details.append(
                    "Algorithm is HS256 but signature seems missing or very short."
                )
        else:
            algo = "N/A"

        # --- Analyze Payload Claims ---
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        time_buffer = datetime.timedelta(minutes=1)  # Allow small clock skew

        # Check Expiration (exp) - NumericDate format (seconds since epoch)
        exp_ts = payload.get("exp")
        if isinstance(exp_ts, (int, float)):
            try:
                exp_dt = datetime.datetime.fromtimestamp(exp_ts, datetime.timezone.utc)
                evidence["exp"] = exp_dt.isoformat()
                if exp_dt < (now_utc - time_buffer):  # Check if expired (with buffer)
                    log_level = (
                        "WARN" if log_level != "ERROR" else log_level
                    )  # Keep ERROR if alg=none
                    details.append(f"Token is EXPIRED (exp: {exp_dt.isoformat()})")
            except (ValueError, TypeError):
                details.append(f"Invalid 'exp' claim format ({exp_ts})")

        # Check Not Before (nbf) - NumericDate format
        nbf_ts = payload.get("nbf")
        if isinstance(nbf_ts, (int, float)):
            try:
                nbf_dt = datetime.datetime.fromtimestamp(nbf_ts, datetime.timezone.utc)
                evidence["nbf"] = nbf_dt.isoformat()
                if nbf_dt > (
                    now_utc + time_buffer
                ):  # Check if used too early (with buffer)
                    log_level = "WARN" if log_level != "ERROR" else log_level
                    details.append(
                        f"Token used BEFORE 'nbf' time (nbf: {nbf_dt.isoformat()})"
                    )
            except (ValueError, TypeError):
                details.append(f"Invalid 'nbf' claim format ({nbf_ts})")

        # Check Issued At (iat) - NumericDate format
        iat_ts = payload.get("iat")
        if isinstance(iat_ts, (int, float)):
            try:
                iat_dt = datetime.datetime.fromtimestamp(iat_ts, datetime.timezone.utc)
                evidence["iat"] = iat_dt.isoformat()
                # Check if issued unreasonably far in past or future
                max_past = timedelta(days=90)  # Example: warn if older than 90 days
                max_future = timedelta(
                    minutes=5
                )  # Example: warn if issued > 5 mins in future
                if iat_dt < (now_utc - max_past):
                    details.append(
                        f"Token issue time ('iat': {iat_dt.isoformat()}) seems very old."
                    )
                if iat_dt > (now_utc + max_future):
                    details.append(
                        f"Token issue time ('iat': {iat_dt.isoformat()}) is in the future?"
                    )
            except (ValueError, TypeError):
                details.append(f"Invalid 'iat' claim format ({iat_ts})")

        # Check for potentially sensitive claims
        sensitive_keys_found = {
            k for k in payload.keys() if k.lower() in POTENTIALLY_SENSITIVE_CLAIMS
        }
        if sensitive_keys_found:
            details.append(
                f"Payload contains potentially sensitive keys: {sorted(list(sensitive_keys_found))}"
            )
            # Log level INFO is probably sufficient unless keys are highly critical
            if log_level == "INFO":
                finding_type = "Passive Scan - JWT Decoded (Contains Sensitive Keys?)"

        # Create payload preview, excluding sensitive keys
        evidence["payload_preview"] = {
            k: (str(v)[:50] + "..." if isinstance(v, str) and len(str(v)) > 50 else v)
            for k, v in payload.items()
            if k.lower() not in POTENTIALLY_SENSITIVE_CLAIMS
        }
        if len(payload) > len(evidence["payload_preview"]):
            evidence["payload_preview"]["..."] = (
                "(some potentially sensitive keys excluded)"
            )

        # --- Log the finding ---
        final_detail = f"Algo: {algo}."
        if details:  # Add specific issues found
            final_detail += " Issues: " + "; ".join(details)
        else:  # If no specific issues, just state basic info
            final_detail += f" Type: {header.get('typ', 'N/A')}. Payload Keys: {list(payload.keys())}"

        addon_instance._log_finding(
            level=log_level,
            finding_type=finding_type,
            url=context,  # Context string acts as URL/location
            detail=final_detail,
            evidence=evidence,
        )

    except (TypeError, ValueError, base64.binascii.Error, json.JSONDecodeError) as e:
        # Log if it looked like a JWT but failed decoding/parsing
        if JWT_STRUCTURE_REGEX.match(token):  # Use regex check here too
            ctx.log.debug(
                f"[Passive Scan] Potential JWT found but failed to decode/parse: {token[:15]}... Error: {e}. Context: {context}"
            )
    except Exception as e:
        # Catch any other unexpected errors during analysis
        ctx.log.warn(
            f"[Passive Scan] Unexpected error analyzing potential JWT in {context}: {e}"
        )


# End of nightcrawler/passive_scans/jwt.py
