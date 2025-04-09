# nightcrawler/utils.py
# Utility functions used across the Nightcrawler addon modules.

from urllib.parse import urlparse
from mitmproxy import http, ctx
from typing import Optional, Set


def is_in_scope(url: str, target_domains: Set[str]) -> bool:
    """
    Checks if the given URL's hostname matches or is a subdomain of any domain
    in the target_domains set. Ignores port number.
    """
    if not url or not target_domains:
        return False
    try:
        # Use hostname which excludes the port number
        hostname = urlparse(url).hostname
        if not hostname:
            # Handle cases like IP addresses without scheme, or invalid URLs
            return False
        # Check if hostname exactly matches or ends with '.<scope_domain>'
        return any(
            hostname == scope_domain or hostname.endswith(f".{scope_domain}")
            for scope_domain in target_domains
            if scope_domain
        )
    except Exception as e:
        # Log error if URL parsing fails for some reason
        # ctx.log.debug(f"Error parsing URL '{url}' in is_in_scope: {e}") # Potrebbe servire ctx qui
        return False  # Treat parsing errors as out of scope


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
        # --- AGGIUNTA DEBUG ---
        ctx.log.debug(
            f"[Create Sig] Checking request: {request.method} {request.pretty_url}"
        )
        ctx.log.debug(
            f"[Create Sig]   Raw Query Object (request.query): {request.query!r}"
        )  # repr() might show more detail
        # --------------------

        parsed_url = urlparse(request.pretty_url)
        # Use scheme, netloc, and path for the base URL part of the signature
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Collect parameter names from GET query and urlencoded POST body
        param_names = set(request.query.keys())  # Get param names from query
        post_param_names = set()
        if request.method == "POST" and request.urlencoded_form:
            post_param_names = set(request.urlencoded_form.keys())
            param_names.update(post_param_names)
        # --- AGGIUNTA DEBUG ---
        ctx.log.debug(
            f"[Create Sig]   GET Param Keys Found: {list(request.query.keys())}"
        )
        ctx.log.debug(
            f"[Create Sig]   POST Form Param Keys Found: {list(post_param_names)}"
        )
        ctx.log.debug(f"[Create Sig]   Combined Param Names Set: {param_names}")
        # --------------------

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
