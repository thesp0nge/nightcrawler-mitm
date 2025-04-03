# nightcrawler/crawler.py
# Contains logic for parsing HTML responses to find new URLs for crawling.

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from mitmproxy import ctx  # For logging via mitmproxy's context
import asyncio  # For Queue type hint
from typing import Set  # For type hint

# Import the utility function for scope checking
try:
    from nightcrawler.utils import is_in_scope
except ImportError:
    import logging

    logging.critical(
        "Could not import is_in_scope from nightcrawler.utils in crawler.py"
    )

    def is_in_scope(url: str, target_domains: set) -> bool:  # Dummy function
        logging.error("is_in_scope function unavailable in crawler.py")
        return False

# Note: The actual crawl worker (_crawl_worker) resides in addon.py


def parse_and_queue_links(
    html_content: str,
    base_url: str,
    discovered_urls: Set[str],  # Shared state from the main addon instance
    crawl_queue: asyncio.Queue,  # Shared state from the main addon instance
    target_domains: Set[str],  # The effective scope set, passed from the main addon
):
    """
    Parses HTML content to find links (<a>, <script>, <img>, <link>, <form>, etc.).
    Adds new, in-scope, absolute URLs to the crawl queue and the discovered set.

    Args:
        html_content: The HTML content string to parse.
        base_url: The URL of the page from which the HTML content was obtained.
        discovered_urls: A set containing all URLs discovered so far (shared state).
        crawl_queue: An asyncio Queue for new URLs to be crawled (shared state).
        target_domains: A set of domain strings defining the crawling/scanning scope.
    """
    new_links_found = 0
    ctx.log.debug(f"[Crawler Parse] Starting HTML parsing for {base_url}")
    try:
        # Using 'html.parser' (built-in). Consider 'lxml' for performance if installed.
        soup = BeautifulSoup(html_content, "html.parser")

        # Find tags that commonly contain links or resource references
        tags_with_links = (
            soup.find_all(["a", "link", "iframe", "frame"], href=True)
            + soup.find_all(
                [
                    "script",
                    "img",
                    "iframe",
                    "frame",
                    "audio",
                    "video",
                    "embed",
                    "source",
                ],
                src=True,
            )
            + soup.find_all("form", action=True)
        )
        # Could also add 'object[data]', 'applet[code]', base[href] etc.

        for tag in tags_with_links:
            # Determine the attribute containing the link/URL
            link_attribute = None
            if tag.name == "form":
                link_attribute = "action"
            elif tag.has_attr("href"):
                link_attribute = "href"
            elif tag.has_attr("src"):
                link_attribute = "src"
            # Add other attributes like 'data' if needed

            if not link_attribute:
                continue

            link = tag.get(link_attribute)
            if not link:
                continue  # Skip empty attributes

            link_str = link.strip()

            # Basic filter for non-web schemes (javascript:, mailto:, data:, blob:, etc.)
            # Allows relative paths (/, ?, #) and http/https
            scheme_check = urlparse(link_str).scheme
            if scheme_check and scheme_check.lower() not in ["http", "https"]:
                # Allow relative URLs which have no scheme initially
                if (
                    ":" in link_str
                ):  # A crude check for absolute URLs with non-http(s) schemes
                    # ctx.log.debug(f"[Crawler Parse] Skipping non-web scheme link: {link_str[:50]}...") # Verbose
                    continue

            # Resolve the link to an absolute URL based on the page's base URL
            try:
                absolute_url = urljoin(base_url, link_str)
            except ValueError:
                ctx.log.debug(
                    f"[Crawler Parse] Skipping invalid URL derived from '{link_str}'"
                )
                continue

            # Clean the URL: remove fragment (#section) and ensure http/https scheme
            try:
                parsed_uri = urlparse(absolute_url)
                if parsed_uri.scheme not in ["http", "https"]:
                    continue  # Only interested in HTTP/HTTPS links
                # Rebuild URL without fragment
                absolute_url = parsed_uri._replace(fragment="").geturl()
            except ValueError:
                ctx.log.debug(
                    f"[Crawler Parse] Skipping malformed absolute URL: {absolute_url}"
                )
                continue

            # Avoid re-adding the page's own URL (after fragment removal) or URLs with no path
            if absolute_url == base_url or not urlparse(absolute_url).path:
                continue

            # --- Scope and Duplicate Check ---
            # Use the utility function imported from utils.py, passing the effective scope
            if (
                is_in_scope(absolute_url, target_domains)
                and absolute_url not in discovered_urls
            ):
                # If it's in scope and we haven't seen it before:
                discovered_urls.add(
                    absolute_url
                )  # Add to the master set of discovered URLs
                crawl_queue.put_nowait(
                    absolute_url
                )  # Add to the queue for the crawl worker
                new_links_found += 1
                ctx.log.info(f"[CRAWLER DISCOVERY] Found new URL: {absolute_url}")

        # Log summary after parsing the whole page
        if new_links_found > 0:
            ctx.log.debug(
                f"[Crawler Parse] Added {new_links_found} new unique URLs to crawl queue from {base_url}. Queue size now: {crawl_queue.qsize()}"
            )
        # else:
        # ctx.log.debug(f"[Crawler Parse] No new URLs found in scope from {base_url}") # Can be verbose

    except Exception as e:
        # Log exceptions during parsing, potentially including traceback for debugging
        # import traceback
        # ctx.log.error(f"[CRAWLER] Error parsing HTML from {base_url}: {e}\n{traceback.format_exc()}")
        ctx.log.warn(f"[CRAWLER] Error parsing HTML from {base_url}: {e}")
