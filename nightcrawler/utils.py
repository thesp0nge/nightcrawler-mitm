# # nightcrawler/utils.py
from urllib.parse import urlparse
from mitmproxy import http
from typing import Optional, Set, List, Any


def is_in_scope(url: str, target_domains: Set[str]) -> bool:
    """Checks if the given URL's hostname is in scope."""
    if not url or not target_domains:
        return False
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        return any(
            hostname == domain or hostname.endswith(f".{domain}")
            for domain in target_domains
        )
    except Exception:
        return False


def create_target_signature(request: http.Request, logger: Any) -> Optional[str]:
    """
    Creates a unique signature for a scan target, logging with the provided logger.
    """
    try:
        logger.debug(
            f"[Create Sig] Checking request: {request.method} {request.pretty_url}"
        )

        parsed_url = urlparse(request.pretty_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        param_names = set(request.query.keys())
        if request.method == "POST" and request.urlencoded_form:
            param_names.update(request.urlencoded_form.keys())

        logger.debug(f"[Create Sig]   Combined Param Names: {param_names}")
        if not param_names:
            logger.debug(f"[Create Sig]   No parameters found, returning None.")
            return None

        signature = (
            f"{request.method}::{base_url}::{','.join(sorted(list(param_names)))}"
        )
        logger.debug(f"[Create Sig]   Generated Signature: {signature}")
        return signature
    except Exception as e:
        logger.error(
            f"[Create Sig] Error generating signature for {request.pretty_url}: {e}"
        )
        return None
