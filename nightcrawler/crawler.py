# nightcrawler/crawler.py
# Contains logic for discovering and queuing new targets (links and forms) from HTML content.

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from typing import TYPE_CHECKING
from mitmproxy.http import Request

# Import the utility functions directly
from .utils import is_in_scope, create_target_signature

if TYPE_CHECKING:
    from .addon import MainAddon


def discover_and_queue_targets(
    response_text: str, base_url: str, addon_instance: "MainAddon"
):
    """
    Parses HTML content to find both hyperlinks (for crawling AND active scanning)
    and forms (for active scanning). Queues discovered items to the appropriate worker.
    """
    if not response_text:
        return

    logger = addon_instance.logger
    logger.debug(f"[Discovery] Parsing content from {base_url} for new targets.")

    try:
        soup = BeautifulSoup(response_text, "html.parser")
    except Exception as e:
        logger.warn(
            f"[Discovery] BeautifulSoup failed to parse HTML from {base_url}: {e}"
        )
        return

    # --- 1. Discover and Queue Hyperlinks ---
    tags_with_links = soup.find_all(["a", "link"], href=True)
    for tag in tags_with_links:
        link = tag.get("href")
        if not link:
            continue

        try:
            absolute_url = urljoin(base_url, link.strip())
            parsed_url = urlparse(absolute_url)
            # Clean fragment from URL
            absolute_url = parsed_url._replace(fragment="").geturl()
        except ValueError:
            continue  # Skip malformed links

        if is_in_scope(absolute_url, addon_instance.effective_scope):
            # --- CRAWLER LOGIC ---
            # Add to discovered URLs for crawling to find more links/forms
            if absolute_url not in addon_instance.discovered_urls:
                addon_instance.discovered_urls.add(absolute_url)
                addon_instance.crawl_queue.put_nowait(absolute_url)
                logger.info(
                    f"[CRAWLER DISCOVERY] Queued new link for crawling: {absolute_url}"
                )

            # --- ACTIVE SCAN LOGIC FOR LINKS WITH PARAMETERS ---
            # If the link has query parameters, treat it as a target for active scanning
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                # Create a mock GET request to generate a signature
                mock_req = Request.make("GET", absolute_url)
                mock_req.query = query_params  # Set query for signature function

                target_signature = create_target_signature(mock_req, logger)

                if (
                    target_signature
                    and target_signature not in addon_instance.scanned_targets
                ):
                    addon_instance.scanned_targets.add(target_signature)
                    scan_details = {
                        "url": absolute_url,
                        "method": "GET",
                        "params": query_params,
                        "data": {},
                        "headers": {"User-Agent": addon_instance.user_agent},
                        "cookies": {},
                    }
                    addon_instance.scan_queue.put_nowait(scan_details)
                    logger.info(
                        f"[SCAN QUEUE (from Link)] Add Target: {target_signature}"
                    )

    # --- 2. Discover and Queue Forms for Active Scanning ---
    all_forms = soup.find_all("form")
    if all_forms:
        logger.debug(f"[Discovery] Found {len(all_forms)} form(s) on {base_url}.")

    for form in all_forms:
        action = form.get("action", "")
        target_url = urljoin(base_url, action)
        method = form.get("method", "GET").upper()

        form_params = {
            inp.get("name"): inp.get("value", "nightcrawler_test")
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("name")
        }
        if not form_params:
            continue

        is_get_form = method == "GET"
        mock_req = Request.make(
            method,
            target_url,
            urlencode(form_params).encode() if not is_get_form else b"",
            {"Content-Type": "application/x-www-form-urlencoded"}
            if not is_get_form
            else {},
        )
        if is_get_form:
            mock_req.query = form_params
        else:
            mock_req.urlencoded_form = form_params

        target_signature = create_target_signature(mock_req, logger)

        if target_signature and target_signature not in addon_instance.scanned_targets:
            addon_instance.scanned_targets.add(target_signature)
            scan_details = {
                "url": target_url,
                "method": method,
                "params": form_params if is_get_form else {},
                "data": form_params if not is_get_form else {},
                "headers": {"User-Agent": addon_instance.user_agent},
                "cookies": {},
            }
            addon_instance.scan_queue.put_nowait(scan_details)
            logger.info(f"[SCAN QUEUE (from Form)] Add Target: {target_signature}")
        elif target_signature:
            logger.debug(
                f"[Discovery] Skipping form target (already scanned): {target_signature}"
            )
