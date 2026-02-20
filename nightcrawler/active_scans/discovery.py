# nightcrawler/active_scans/discovery.py
# Active scanner for discovering hidden content (files/directories) using a wordlist.

import httpx
import time
from typing import Dict, Any, List, Set, TYPE_CHECKING
from urllib.parse import urljoin, urlparse
import os
from nightcrawler.active_scans.base import ActiveScanner

# Type hint for MainAddon to allow calling its methods like _log_finding
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class ContentDiscoveryScanner(ActiveScanner):
    name: str = "Content Discovery"

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Extracts base directory from URL and runs discovery scan."""
        url = target_info["url"]
        try:
            parsed_url = urlparse(url)
            dir_path = os.path.dirname(parsed_url.path)
            if not dir_path.endswith("/"):
                dir_path += "/"
            base_dir_url = urljoin(url, dir_path)
            
            await scan_content_discovery(
                base_dir_url,
                self.addon_instance.discovery_wordlist,
                cookies,
                http_client,
                self.addon_instance,
                self.logger
            )
        except Exception as e:
            self.logger.debug(f"[Discovery Scan] Error determining base dir for {url}: {e}")

async def scan_content_discovery(
    base_dir_url: str,
    wordlist: Set[str],
    cookies: Dict[str, str],
    http_client: httpx.AsyncClient,
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Scans a base directory URL for hidden content using a wordlist.
    Sends HEAD requests for efficiency and logs non-404 responses.
    """
    if not wordlist:
        return

    logger.debug(
        f"[Discovery Scan] Starting for base URL: {base_dir_url} with {len(wordlist)} words."
    )

    # Prepare common headers, using the logger for debug
    request_headers = {"User-Agent": addon_instance.user_agent}
    if cookies:
        request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        logger.debug(f"[Discovery Scan] Using cookies for requests to {base_dir_url}")

    for item in wordlist:
        # Construct the full URL to test
        target_url = urljoin(base_dir_url, item)

        try:
            # Use HEAD request for efficiency - we only need the status code
            response = await http_client.head(
                target_url,
                headers=request_headers,
                follow_redirects=False,
                timeout=10.0,
            )

            # Analyze Response: We are interested in anything that is NOT a 404 Not Found
            status_code = response.status_code
            if status_code != 404:
                level = "ERROR" if 200 <= status_code < 300 else "WARN"
                finding_type = (
                    "Content Discovery - File/Dir Found"
                    if 200 <= status_code < 300
                    else f"Content Discovery - Interesting Status {status_code}"
                )

                addon_instance._log_finding(
                    level=level,
                    finding_type=finding_type,
                    url=target_url,
                    detail=f"Found accessible resource with status code {status_code}.",
                    evidence={"status_code": status_code, "wordlist_item": item},
                    confidence="LOW",
                )

        except httpx.ConnectError as e:
            logger.debug(f"[Discovery Scan] Connection error for {target_url}: {e}")
        except httpx.TimeoutException:
            logger.warn(f"[Discovery Scan] Timeout for {target_url}")
        except Exception as e:
            logger.debug(f"[Discovery Scan] Exception probing {target_url}: {e}")

    logger.debug(f"[Discovery Scan] Finished for base URL: {base_dir_url}")
