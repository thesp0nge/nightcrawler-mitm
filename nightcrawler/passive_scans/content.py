# nightcrawler/passive_scans/content.py
# Passive checks related to the content/body of HTTP responses.

import re
from mitmproxy import http, ctx
from typing import Optional, List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Define regex patterns here (or import them from utils/config if moved)
# Keywords often associated with sensitive information leakage
COMMON_SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "client_secret",
    "access_key",
    "sessionid",
    "connect.sid",
    "auth",
    "bearer",
    "credentials",
    "database_url",
    "private_key",
]
# Basic Regex for potential API keys or high-entropy secrets near keywords.
# WARNING: High risk of False Positives! Needs tuning.
API_KEY_REGEX = re.compile(
    r"""
    (?i)                                      # Case-insensitive matching
    # Keywords - expanded list, ensure word boundaries
    \b(?:key|token|secret|password|auth|bearer|pwd|pass|api[-_]?key|session|credential|access[-_]?key|secret[-_]?key|client[-_]?id)\b
    \s*[:=()\[\]"']+\s* # Separators (broader set)
    (['"]?)                                   # Optional opening quote (Group 1)
    (                                         # Potential value (Group 2)
        (?:[a-z0-9\-_/+]{20,})                # Alphanumeric + common token chars (increased min length to 20)
        |                                     # OR
        (?:[a-f0-9]{32,})                     # Hex string (e.g., MD5, SHA1 etc.), min 32 length
    )
    \1                                        # Match optional closing quote
    """,
    re.VERBOSE | re.IGNORECASE,
)
# Basic Regex for potential AWS Access Key ID prefix
AWS_KEY_ID_REGEX = re.compile(
    r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"
)
# Regex for potential private key file headers
PRIVATE_KEY_HEADER_REGEX = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |[A-Z]+ )?PRIVATE KEY-----"
)


def check_info_disclosure(
    response: http.Response, url: str, addon_instance: "MainAddon"
):
    """
    Checks response body for sensitive keywords, potential API keys,
    and private key headers. Logs findings using the provided addon_instance.
    NOTE: Comment detection is temporarily skipped.
    """
    # Use response.text safely (it's Optional[str])
    response_text = response.text
    if not response_text:
        return  # Skip if no text body (e.g., images, binary files)

    # Limit
    max_size_to_check = 2 * 1024 * 1024  # 2MB limit for content checks
    if response.content and len(response.content) > max_size_to_check:
        ctx.log.debug(
            f"[Passive Content Check] Response body from {url} too large ({len(response.content)} bytes), skipping content analysis."
        )
        return

    findings: List[Dict[str, Any]] = []  # Store findings as dicts before logging
    content_type = response.headers.get("Content-Type", "").lower()

    # 1. Comment detection
    try:
        if (
            "html" in content_type
            or "javascript" in content_type
            or "xml" in content_type
        ):
            # Check if response_text contains "<!--" or "//" or "/*"
            if (
                "<!--" in response_text
                or "//" in response_text
                or "/*" in response_text
            ):
                # Call the logging function
                addon_instance._log_finding(
                    level="INFO",
                    finding_type="Passive Scan - Comments Found",
                    url=url,
                    detail="HTML/JS/XML style comments found. Manual review recommended.",
                    evidence=None,
                )
    except Exception as e:
        ctx.log.debug(f"Error during comment check at {url}: {e}")

    # 2. Sensitive Keywords Context (Basic check, needs refinement)
    try:
        matches_per_keyword_limit = 3
        for keyword in COMMON_SENSITIVE_KEYWORDS:
            matches_found_count = 0
            # Use finditer for memory efficiency and context
            # Regex looks for keyword, separator(s), potential value
            pattern = (
                r'([\'"]?'
                + re.escape(keyword)
                + r'[\'"]?\s*[:=()\[\]"\' ]+\s*[\'"]?)([^\s,\'"]{6,})'
            )
            for match in re.finditer(pattern, response_text, re.IGNORECASE | re.DOTALL):
                if matches_found_count >= matches_per_keyword_limit:
                    break  # Stop checking for this keyword after finding a few matches

                context_start_str, potential_value = match.groups()
                # Basic filtering to reduce noise
                if (
                    "<" not in potential_value
                    and ">" not in potential_value
                    and potential_value.lower()
                    not in ["null", "true", "false", "none", "undefined", "yes", "no"]
                    and len(potential_value) < 100
                ):  # Avoid matching huge blobs
                    # Extract context snippet around the match
                    start_idx = max(0, match.start() - 30)
                    end_idx = min(len(response_text), match.end() + 30)
                    # Clean context snippet (remove newlines)
                    context_window = (
                        response_text[start_idx:end_idx]
                        .replace("\n", " ")
                        .replace("\r", "")
                    )
                    findings.append(
                        {
                            "level": "WARN",  # Requires verification
                            "type": "Keyword Context",
                            "detail": f"Keyword '{keyword}' found near potential value.",
                            "evidence": {"match_context": f"...{context_window}..."},
                        }
                    )
                    matches_found_count += 1
    except Exception as e:
        ctx.log.debug(f"Regex error during keyword check at {url}: {e}")

    # 3. API Key / Secret Patterns (High potential for FPs)
    try:
        # Findall returns list of tuples if regex has groups
        potential_keys = API_KEY_REGEX.findall(response_text)
        aws_keys = AWS_KEY_ID_REGEX.findall(response_text)

        keys_reported, max_keys = 0, 5  # Limit reported findings per type
        for key_match in potential_keys:
            if keys_reported >= max_keys:
                break
            # key_match should be (separator_part, key_value_part) from regex groups
            if len(key_match) == 2:
                findings.append(
                    {
                        "level": "WARN",  # Potential finding, needs verification
                        "type": "Potential Key/Secret Pattern",
                        "detail": f"Regex pattern match for key/secret near '{key_match[0].strip()[:20]}'. Verify manually.",
                        # Log only partial info for security
                        "evidence": {
                            "matched_pattern_suffix": f"...{key_match[1][-6:]}"
                        },
                    }
                )
                keys_reported += 1

        aws_keys_reported, max_aws_keys = 0, 3
        for aws_key in aws_keys:
            if aws_keys_reported >= max_aws_keys:
                break
            findings.append(
                {
                    "level": "WARN",  # Potential finding
                    "type": "Potential AWS Key ID Pattern",
                    "detail": "Regex pattern match for AWS Key ID. Verify manually.",
                    "evidence": {
                        "matched_pattern_prefix": f"{aws_key[:8]}..."
                    },  # Show prefix
                }
            )
            aws_keys_reported += 1
    except Exception as e:
        ctx.log.debug(f"Regex error during API key check at {url}: {e}")

    # 4. Private Key Headers
    try:
        # Use search as we only need to find one instance
        if PRIVATE_KEY_HEADER_REGEX.search(response_text):
            findings.append(
                {
                    "level": "ERROR",  # This is usually critical if confirmed
                    "type": "Potential Private Key",
                    "detail": "Found '-----BEGIN...PRIVATE KEY-----' pattern. Critical if confirmed.",
                    "evidence": None,  # Avoid logging the key itself
                }
            )
    except Exception as e:
        ctx.log.debug(f"Regex error during private key check at {url}: {e}")

    # --- Log all findings gathered in this function ---
    # Use the centralized logging method from the addon instance
    unique_finding_keys = (
        set()
    )  # Track logged findings to avoid duplicates per response/type
    for finding in findings:
        # Create a simple key to deduplicate based on type and maybe detail prefix
        finding_key = f"{finding['type']}_{finding['detail'][:30]}"
        if finding_key not in unique_finding_keys:
            addon_instance._log_finding(
                level=finding["level"],
                finding_type=f"Passive Scan - Info Disclosure ({finding['type']})",  # Add prefix
                url=url,
                detail=finding["detail"],
                evidence=finding.get("evidence"),
            )
            unique_finding_keys.add(finding_key)


# End of nightcrawler/passive_scans/content.py
