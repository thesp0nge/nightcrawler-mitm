# nightcrawler/passive_scans/content.py
# Passive checks related to the content/body of HTTP responses.

import re
from mitmproxy import http, ctx
from typing import Optional, List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    # To avoid circular import for type hinting only
    from nightcrawler.addon import MainAddon

# Define a list of tuples, where each tuple contains:
# (Finding Type, Regex Pattern, Severity Level)
SENSITIVE_DATA_PATTERNS = [
    ("Potential Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |[A-Z]+ )?PRIVATE KEY-----"), "ERROR"),
    ("Potential AWS Key ID", re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"), "WARN"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z]{35}"), "WARN"),
    ("Stripe API Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "WARN"),
    ("Slack Token", re.compile(r"xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}"), "WARN"),
    ("Generic API Key", re.compile(r"[Aa]pi[Kk]ey\s*[:=]\s*[0-9a-zA-Z]{32,}", re.IGNORECASE), "WARN"),
    ("Credit Card Number", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b"), "WARN"),
    ("Social Security Number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "WARN"),
]

def check_info_disclosure(
    response: http.Response, url: str, addon_instance: "MainAddon", logger: Any
):
    """
    Checks response body for sensitive keywords, potential API keys,
    and private key headers. Logs findings using the provided addon_instance.
    """
    response_text = response.text
    if not response_text:
        return

    max_size_to_check = 2 * 1024 * 1024  # 2MB limit
    if response.content and len(response.content) > max_size_to_check:
        logger.debug(f"[Content Check] Response body from {url} too large, skipping.")
        return

    for finding_type, pattern, level in SENSITIVE_DATA_PATTERNS:
        try:
            matches = pattern.finditer(response_text)
            for match in matches:
                addon_instance._log_finding(
                    level=level,
                    finding_type=f"Passive Scan - Info Disclosure ({finding_type})",
                    url=url,
                    detail=f"Found a potential '{finding_type}' pattern.",
                    evidence={"match": match.group(0)[:100]}, # Log a snippet
                )
        except Exception as e:
            logger.debug(f"Regex error during {finding_type} check at {url}: {e}")


# End of nightcrawler/passive_scans/content.py
