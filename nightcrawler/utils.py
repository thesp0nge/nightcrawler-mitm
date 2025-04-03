# nightcrawler/utils.py
# Utility functions used across the Nightcrawler addon modules.

from urllib.parse import urlparse
from mitmproxy import http
from typing import Optional, Set


def is_in_scope(url: str, target_domains: Set[str]) -> bool:
    """
    Checks if the given URL's domain matches or is a subdomain of any domain
    in the target_domains set.

    Args:
        url: The URL string to check.
        target_domains: A set of domain strings defining the scope.

    Returns:
        True if the URL is in scope, False otherwise.
    """
    if not url or not target_domains:
        return False
    try:
        domain = urlparse(url).netloc
        if not domain:  # Handle cases like relative paths passed unexpectedly
            return False
        # Check if the domain exactly matches or ends with '.<scope_domain>'
        return any(
            domain == scope_domain or domain.endswith(f".{scope_domain}")
            for scope_domain in target_domains
            if scope_domain
        )
    except Exception:
        # Consider malformed URLs as out of scope
        return False


def create_target_signature(request: http.Request) -> Optional[str]:
    """
    Creates a unique signature for a potential active scan target,
    based on METHOD, URL path, and sorted parameter names (GET/POST form).
    Used for deduplicating scan targets.

    Args:
        request: The mitmproxy http.Request object.

    Returns:
        A unique string signature if parameters are found, None otherwise.
    """
    try:
        parsed_url = urlparse(request.pretty_url)
        # Use scheme, netloc, and path for the base URL part of the signature
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Collect parameter names from GET query and urlencoded POST body
        param_names = set(request.query.keys())
        if request.method == "POST" and request.urlencoded_form:
            param_names.update(request.urlencoded_form.keys())
        # TODO: Extend to consider JSON body keys, XML structures, etc. if needed.

        # If no parameters are identified, don't generate a scan signature for this request
        if not param_names:
            return None

        # Sort parameter names alphabetically to ensure the signature is consistent
        # regardless of the original parameter order.
        signature = (
            f"{request.method}::{base_url}::{','.join(sorted(list(param_names)))}"
        )
        return signature
    except Exception:
        # Handle potential errors during parsing (e.g., malformed request)
        return None
