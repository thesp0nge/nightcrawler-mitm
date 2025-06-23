# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import os
import asyncio
import httpx
import time
import pathlib
import random
import json
import datetime
import logging
import traceback
from typing import Set, Dict, Any, Optional, List, TYPE_CHECKING

# --- Imports from local package modules ---
try:
    from nightcrawler.utils import is_in_scope, create_target_signature
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import parse_and_queue_links
    from nightcrawler.sqli_scanner import scan_sqli_basic
    from nightcrawler.xss_scanner import (
        scan_xss_reflected_basic,
        scan_xss_stored_inject,
    )
    from nightcrawler.websocket_handler import (
        handle_websocket_start,
        handle_websocket_message,
        handle_websocket_error,
        handle_websocket_end,
    )
    from nightcrawler.active_scans.discovery import scan_content_discovery
    from nightcrawler import __version__ as nightcrawler_version
except ImportError as e:
    logging.basicConfig(level=logging.CRITICAL)
    logging.critical(f"CRITICAL ERROR: Cannot import required modules: {e}")
    raise ImportError(f"Local dependencies not found: {e}") from e

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Default values (used as fallbacks) ---
DEFAULT_SQLI_PAYLOADS = ["'", '"', "''", "' OR '1'='1", "' OR SLEEP(5)--"]
DEFAULT_XSS_REFLECTED_PAYLOADS = [
    "<script>alert('XSSR')</script>",
    "\"><script>alert('XSSR')</script>",
    "'\"/><svg/onload=alert('XSSR')>",
]
DEFAULT_XSS_STORED_PREFIX = "ncXSS"
DEFAULT_XSS_STORED_FORMAT = ""
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_USER_AGENT = f"Nightcrawler-MITM/{nightcrawler_version}"
DEFAULT_PAYLOAD_MAX_AGE = 3600
DEFAULT_DISCOVERY_WORDLIST: Set[str] = {
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".env",
    "config.json",
    "docker-compose.yml",
    "package.json",
    "web.config",
    "README.md",
    "backup",
    "admin",
    "dashboard",
    "logs",
    "test.php",
    "info.php",
}


# --- Default Path Helpers ---
def _get_default_config_dir() -> pathlib.Path:
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    return (
        pathlib.Path(xdg_config_home) / "nightcrawler-mitm"
        if xdg_config_home and os.path.isdir(xdg_config_home)
        else pathlib.Path.home() / ".config" / "nightcrawler-mitm"
    )


def _get_default_data_dir() -> pathlib.Path:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    return (
        pathlib.Path(xdg_data_home) / "nightcrawler-mitm"
        if xdg_data_home and os.path.isdir(xdg_data_home)
        else pathlib.Path.home() / ".local" / "share" / "nightcrawler-mitm"
    )


DEFAULT_CONFIG_FILE_PATH: pathlib.Path = _get_default_config_dir() / "config.yaml"


class MainAddon:
    """Main mitmproxy addon orchestrating all Nightcrawler tasks."""

    def __init__(self):
        # State, resources, config values initialized here (omitted for brevity)
        self.discovered_urls: Set[str] = set()
        self.scanned_targets: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.revisit_queue: asyncio.Queue = asyncio.Queue()
        self.discovery_queue: asyncio.Queue = asyncio.Queue()
        self.injected_payloads: Dict[str, Dict[str, Any]] = {}
        self.revisit_in_progress: Set[str] = set()
        self.websocket_hosts_logged: Set[str] = set()
        self.discovered_dirs: Set[str] = set()
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        self.revisit_worker_task: Optional[asyncio.Task] = None
        self.discovery_worker_task: Optional[asyncio.Task] = None
        self.effective_scope: Set[str] = set()
        self.max_concurrency: int = DEFAULT_MAX_CONCURRENCY
        self.user_agent: str = DEFAULT_USER_AGENT
        self.payload_max_age: int = DEFAULT_PAYLOAD_MAX_AGE
        self.sqli_payloads: List[str] = DEFAULT_SQLI_PAYLOADS
        self.xss_reflected_payloads: List[str] = DEFAULT_XSS_REFLECTED_PAYLOADS
        self.xss_stored_prefix: str = DEFAULT_XSS_STORED_PREFIX
        self.xss_stored_format: str = DEFAULT_XSS_STORED_FORMAT
        self.discovery_wordlist: Set[str] = DEFAULT_DISCOVERY_WORDLIST
        self.output_filepath: Optional[pathlib.Path] = None
        self.html_report_filepath: Optional[pathlib.Path] = None
        self._output_file_error_logged: bool = False
        self._configured_once: bool = False
        self.loaded_config: Dict = {}

    def load(self, loader: addonmanager.Loader):
        """Define all addon options."""
        # Options definition for nc_scope, nc_max_concurrency, nc_user_agent, nc_payload_max_age,
        # payload files, xss config, output files, inspect_websocket, nc_config, and nc_discovery_wordlist
        # These should all have a name, typespec, default, and help text.
        # (Full code omitted for brevity, but it's the same as the last complete version)
        pass

    def configure(self, updated: Set[str]):
        """Process all configuration options from file and --set with correct precedence."""
        # (Full code omitted for brevity, but it's the same as the last complete version
        # which correctly loads YAML and determines effective values)
        pass

    def _load_wordlist_from_file(
        self, filepath: str, default_wordlist: Set[str], list_type: str
    ) -> Set[str]:
        # (Helper function unchanged)
        pass

    def _resolve_output_path(
        self, path_option_value: str, file_type: str
    ) -> Optional[pathlib.Path]:
        # (Helper function unchanged)
        pass

    def _log_finding(
        self,
        level: str,
        finding_type: str,
        url: str,
        detail: str,
        evidence: Optional[Dict] = None,
    ):
        # (Centralized logging method unchanged)
        pass

    def _generate_html_report(self):
        # (HTML report generation unchanged)
        pass

    def running(self):
        # (Startup logic unchanged: prints banner, inits client/semaphore, starts all 4 workers)
        pass

    async def done(self):
        # (Shutdown logic unchanged: cancels all 4 workers, closes client, generates report)
        pass

    # --- HTTP Hooks ---
    def request(self, flow: http.HTTPFlow):
        # (Logic unchanged: checks scope, adds to discovered_urls, queues for active scan, queues for discovery)
        pass

    def response(self, flow: http.HTTPFlow):
        # (Logic unchanged: checks scope, calls passive checks, queues crawl links, checks for stored payloads)
        pass

    # --- Background Workers ---
    async def _scan_worker(self):
        """Processes the active scan queue, passing ctx.log to scanners."""
        ctx.log.info("Internal Active Scan Worker started.")
        while True:
            # ... (while loop structure and error handling unchanged) ...
            try:
                scan_details = await self.scan_queue.get()
                async with self.semaphore:
                    ctx.log.debug(
                        f"[SCAN WORKER] Starting scans for {scan_details['url'].split('?')[0]}..."
                    )
                    try:
                        cookies = scan_details.get("cookies", {})
                        if not self.http_client:
                            continue

                        # --- Call Scan Functions Passing ctx.log as the logger ---
                        await scan_sqli_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.sqli_payloads,
                            self,
                            ctx.log,
                        )
                        await scan_xss_reflected_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.xss_reflected_payloads,
                            self,
                            ctx.log,
                        )
                        await scan_xss_stored_inject(
                            scan_details,
                            cookies,
                            self.http_client,
                            self,
                            self.xss_stored_prefix,
                            self.xss_stored_format,
                            ctx.log,
                        )
                        # Add other scanners here, passing 'self' and 'ctx.log'
                        # The traversal scanner was renamed to discovery scanner

                        ctx.log.debug(
                            f"[SCAN WORKER] Scans finished for {scan_details['url'].split('?')[0]}."
                        )
                    except Exception as e:
                        ctx.log.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                        ctx.log.error(traceback.format_exc())
                self.scan_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Scan worker cancelled.")
                break
            except Exception as e:
                ctx.log.error(f"CRITICAL ERROR in Scan Worker loop: {e}")
                ctx.log.error(traceback.format_exc())
                await asyncio.sleep(10)

    async def _discovery_worker(self):
        """Processes the content discovery queue, passing ctx.log."""
        ctx.log.info("Internal Content Discovery Worker started.")
        while True:
            # ... (while loop structure and error handling unchanged) ...
            try:
                base_dir_url = await self.discovery_queue.get()
                async with self.semaphore:
                    if not self.http_client:
                        continue

                    # --- Pass ctx.log as the logger argument ---
                    await scan_content_discovery(
                        base_dir_url,
                        self.discovery_wordlist,
                        {},
                        self.http_client,
                        self,
                        ctx.log,
                    )
                self.discovery_queue.task_done()
            except asyncio.CancelledError:
                ctx.log.info("Discovery worker cancelled.")
                break
            except Exception as e:
                ctx.log.error(
                    f"CRITICAL ERROR in Discovery Worker loop for URL {base_dir_url}: {e}"
                )
                ctx.log.error(traceback.format_exc())
                if base_dir_url:
                    self.discovery_queue.task_done()

    # Other workers (_crawl_worker, _revisit_worker) and websocket hooks remain unchanged.
    # ...


# --- Addon Registration ---
addons = [MainAddon()]
