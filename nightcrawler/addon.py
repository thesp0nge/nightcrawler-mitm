# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import asyncio
import httpx
import time
import pathlib  # Needed for reading payload files
import random  # Needed for payload ID generation
from typing import Set, Dict, Any, Optional, List

# --- Imports from local package modules ---
try:
    # config.py is now minimal or empty for user settings
    from nightcrawler.utils import is_in_scope, create_target_signature
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import parse_and_queue_links
    from nightcrawler.sqli_scanner import scan_sqli_basic

    # Import both XSS scanning functions
    from nightcrawler.xss_scanner import (
        scan_xss_reflected_basic,
        scan_xss_stored_inject,
    )
except ImportError as e:
    import logging

    logging.basicConfig(level=logging.CRITICAL)
    logging.critical(f"CRITICAL ERROR: Cannot import required modules: {e}")
    raise ImportError(f"Local dependencies not found: {e}") from e

# Default values used if options are not set or files are invalid
DEFAULT_SQLI_PAYLOADS = ["'", '"', "''", "' OR '1'='1", "' OR SLEEP(5)--"]
DEFAULT_XSS_REFLECTED_PAYLOADS = [
    "<script>alert('XSSR')</script>",
    "\"><script>alert('XSSR')</script>",
    "'\"/><svg/onload=alert('XSSR')>",
]
DEFAULT_XSS_STORED_PREFIX = "ncXSS"
DEFAULT_XSS_STORED_FORMAT = ""
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_USER_AGENT = (
    f"Nightcrawler-MITM/{getattr(__import__('nightcrawler'), '__version__', 'unknown')}"
)
DEFAULT_PAYLOAD_MAX_AGE = 3600  # 1 hour


class MainAddon:
    """
    Main mitmproxy addon orchestrating background security tasks.
    Configuration is primarily handled via mitmproxy's '--set name=value'
    command-line options (e.g., --set nc_scope=example.com).
    """

    def __init__(self):
        """Initializes the addon's state (queues, sets). No logging here."""
        self.discovered_urls: Set[str] = set()
        self.scanned_targets: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.revisit_queue: asyncio.Queue = asyncio.Queue()
        self.injected_payloads: Dict[str, Dict[str, Any]] = {}  # probe_id -> {details}

        # Resources initialized in 'running' after options are processed
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        self.revisit_worker_task: Optional[asyncio.Task] = None

        # --- Configuration values, populated in 'configure' ---
        self.effective_scope: Set[str] = set()
        self.max_concurrency: int = DEFAULT_MAX_CONCURRENCY
        self.user_agent: str = DEFAULT_USER_AGENT
        self.payload_max_age: int = DEFAULT_PAYLOAD_MAX_AGE
        self.sqli_payloads: List[str] = DEFAULT_SQLI_PAYLOADS
        self.xss_reflected_payloads: List[str] = DEFAULT_XSS_REFLECTED_PAYLOADS
        self.xss_stored_prefix: str = DEFAULT_XSS_STORED_PREFIX
        self.xss_stored_format: str = DEFAULT_XSS_STORED_FORMAT
        # --------------------------------------------------------

        # Log initial message later in 'running' hook when ctx.log is safe

    def load(self, loader: addonmanager.Loader):
        """Define addon options registerable via mitmproxy's --set."""
        # Note: We only provide the 'name', 'type', 'default', and 'help'.
        # Mitmproxy makes these automatically configurable via '--set <name>=<value>'.
        # No custom command-line flags (like --nc-scope) are defined here anymore.
        loader.add_option(
            name="nc_scope",  # Option name used in --set nc_scope=...
            typespec=str,
            default="",  # Default to empty, requiring user input
            help="REQUIRED: Target scope domain(s), comma-separated (e.g., example.com,sub.example.com).",
        )
        loader.add_option(
            name="nc_max_concurrency",
            typespec=int,
            default=DEFAULT_MAX_CONCURRENCY,
            help=f"Maximum number of concurrent background scan/crawl tasks (Default: {DEFAULT_MAX_CONCURRENCY}).",
        )
        loader.add_option(
            name="nc_user_agent",
            typespec=str,
            default=DEFAULT_USER_AGENT,
            help=f"User-Agent string for requests made by Nightcrawler's workers (Default: {DEFAULT_USER_AGENT}).",
        )
        loader.add_option(
            name="nc_payload_max_age",
            typespec=int,
            default=DEFAULT_PAYLOAD_MAX_AGE,
            help=f"Max age (seconds) for tracking injected payloads for Stored XSS (Default: {DEFAULT_PAYLOAD_MAX_AGE}).",
        )
        loader.add_option(
            name="nc_sqli_payload_file",
            typespec=str,
            default="",  # Default is empty, meaning use built-in list
            help="File containing SQLi payloads (one per line). If set, overrides built-in defaults.",
        )
        loader.add_option(
            name="nc_xss_reflected_payload_file",
            typespec=str,
            default="",  # Default is empty
            help="File containing Reflected XSS payloads (one per line). If set, overrides built-in defaults.",
        )
        loader.add_option(
            name="nc_xss_stored_prefix",
            typespec=str,
            default=DEFAULT_XSS_STORED_PREFIX,
            help=f"Prefix for unique Stored XSS probe IDs (Default: '{DEFAULT_XSS_STORED_PREFIX}').",
        )
        loader.add_option(
            name="nc_xss_stored_format",
            typespec=str,
            default=DEFAULT_XSS_STORED_FORMAT,
            help=f"Format string for Stored XSS probe payload (must contain '{{probe_id}}') (Default: '{DEFAULT_XSS_STORED_FORMAT}').",
        )

    def configure(self, updated: Set[str]):
        """Process options when they are set or updated via --set or config file."""
        # This hook is called after 'load' and whenever options change.
        # We read from ctx.options and store the processed values in self.* attributes.
        ctx.log.debug(f"Configure hook called, processing updated options: {updated}")

        # Use hasattr check to see if initial configuration already happened
        is_initial_config = not hasattr(self, "_configured_once")

        # --- Process Scope ---
        if "nc_scope" in updated or is_initial_config:
            scope_str = ctx.options.nc_scope
            if scope_str:
                self.effective_scope = {
                    s.strip() for s in scope_str.split(",") if s.strip()
                }
                ctx.log.info(f"Target scope set: {self.effective_scope}")
            else:
                self.effective_scope = set()
                # Warning will be issued in 'running' hook if still empty

        # --- Process Max Concurrency ---
        if "nc_max_concurrency" in updated or is_initial_config:
            self.max_concurrency = max(
                1, ctx.options.nc_max_concurrency
            )  # Ensure at least 1
            ctx.log.info(f"Max worker concurrency set to: {self.max_concurrency}")
            # Semaphore will be updated/created in 'running' based on this value

        # --- Process User Agent ---
        if "nc_user_agent" in updated or is_initial_config:
            self.user_agent = (
                ctx.options.nc_user_agent or DEFAULT_USER_AGENT
            )  # Ensure not empty
            ctx.log.info(f"Scan/Crawl User-Agent set to: {self.user_agent}")
            # HTTP client will be updated/created in 'running' based on this value

        # --- Process Payload Max Age ---
        if "nc_payload_max_age" in updated or is_initial_config:
            self.payload_max_age = max(
                60, ctx.options.nc_payload_max_age
            )  # Ensure reasonable minimum age
            ctx.log.info(f"Tracked payload max age set to: {self.payload_max_age}s")

        # --- Process Payload Files ---
        if "nc_sqli_payload_file" in updated or is_initial_config:
            self.sqli_payloads = self._load_payloads_from_file(
                ctx.options.nc_sqli_payload_file, DEFAULT_SQLI_PAYLOADS, "SQLi"
            )
            ctx.log.info(f"Loaded {len(self.sqli_payloads)} SQLi payloads.")

        if "nc_xss_reflected_payload_file" in updated or is_initial_config:
            self.xss_reflected_payloads = self._load_payloads_from_file(
                ctx.options.nc_xss_reflected_payload_file,
                DEFAULT_XSS_REFLECTED_PAYLOADS,
                "Reflected XSS",
            )
            ctx.log.info(
                f"Loaded {len(self.xss_reflected_payloads)} Reflected XSS payloads."
            )

        # --- Process Stored XSS Config ---
        if "nc_xss_stored_prefix" in updated or is_initial_config:
            self.xss_stored_prefix = (
                ctx.options.nc_xss_stored_prefix or DEFAULT_XSS_STORED_PREFIX
            )
            ctx.log.info(f"Stored XSS probe prefix set to: '{self.xss_stored_prefix}'")

        if "nc_xss_stored_format" in updated or is_initial_config:
            format_str = ctx.options.nc_xss_stored_format or DEFAULT_XSS_STORED_FORMAT
            # Basic validation for the placeholder
            if "{probe_id}" not in format_str:
                ctx.log.warn(
                    f"Stored XSS payload format ('{format_str}') does not contain '{{probe_id}}'. Using default: '{DEFAULT_XSS_STORED_FORMAT}'"
                )
                self.xss_stored_format = DEFAULT_XSS_STORED_FORMAT
            else:
                self.xss_stored_format = format_str
            ctx.log.info(
                f"Stored XSS payload format set to: '{self.xss_stored_format}'"
            )

        setattr(self, "_configured_once", True)  # Mark that initial config has run

    def _load_payloads_from_file(
        self, filepath: str, default_payloads: List[str], payload_type: str
    ) -> List[str]:
        """Loads payloads from a file, falling back to defaults on error."""
        # Helper function to load payloads from files specified in options
        if not filepath:
            ctx.log.debug(
                f"No payload file specified for {payload_type}, using {len(default_payloads)} defaults."
            )
            return list(default_payloads)  # Return a copy
        try:
            # Use pathlib for better path handling
            path = pathlib.Path(filepath).resolve()
            ctx.log.debug(f"Attempting to load {payload_type} payloads from: {path}")
            # Read file, split lines, strip whitespace, filter empty lines and comments
            payloads = [
                line.strip()
                for line in path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not payloads:
                ctx.log.warn(
                    f"Payload file '{path}' for {payload_type} is empty or contains only comments. Using defaults."
                )
                return list(default_payloads)  # Return a copy
            ctx.log.info(
                f"Successfully loaded {len(payloads)} {payload_type} payloads from: {path}"
            )
            return payloads
        except FileNotFoundError:
            ctx.log.warn(
                f"Payload file '{filepath}' not found for {payload_type}. Using defaults."
            )
            return list(default_payloads)  # Return a copy
        except Exception as e:
            ctx.log.error(
                f"Error loading payload file '{filepath}' for {payload_type}: {e}. Using defaults."
            )
            return list(default_payloads)  # Return a copy

    def running(self):
        """Initialize resources like HTTP client, semaphore and start workers."""
        # Log addon version and status now that ctx.log is available
        try:
            version = getattr(__import__("nightcrawler"), "__version__", "unknown")
        except ImportError:
            version = "unknown"
        ctx.log.info("=" * 30)
        ctx.log.info(f" Nightcrawler Addon v{version} Running... ")
        ctx.log.info("=" * 30)
        ctx.log.info(f"Effective Scope: {self.effective_scope or 'Not Set (Idle)'}")

        # Initialize/Update Semaphore based on processed option
        # Check if semaphore needs creation or resizing
        if not self.semaphore or self.semaphore._value != self.max_concurrency:
            self.semaphore = asyncio.Semaphore(self.max_concurrency)
            ctx.log.debug(
                f"Semaphore initialized/updated with concurrency {self.max_concurrency}"
            )

        # Initialize/Update HTTP client based on processed options
        if (
            not self.http_client
            or self.http_client.headers.get("User-Agent") != self.user_agent
        ):
            if self.http_client:
                # Schedule closing the old client without blocking
                asyncio.create_task(self.http_client.aclose())
                ctx.log.debug("Scheduled previous HTTP client for closure.")

            self.http_client = httpx.AsyncClient(
                headers={"User-Agent": self.user_agent},  # Use configured UA
                verify=False,  # Corresponds to --ssl-insecure for script requests
                timeout=15.0,
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=self.max_concurrency + 10,
                    max_keepalive_connections=self.max_concurrency,
                ),
            )
            ctx.log.debug(
                f"HTTP Client initialized/updated. User-Agent: {self.user_agent}"
            )

        # Start/Restart worker tasks
        # Cancel existing tasks if they are running before starting new ones
        # (e.g., if config changed causing resources to be recreated)
        if self.crawl_worker_task and not self.crawl_worker_task.done():
            self.crawl_worker_task.cancel()
        self.crawl_worker_task = asyncio.create_task(self._crawl_worker())

        if self.scan_worker_task and not self.scan_worker_task.done():
            self.scan_worker_task.cancel()
        self.scan_worker_task = asyncio.create_task(self._scan_worker())

        if self.revisit_worker_task and not self.revisit_worker_task.done():
            self.revisit_worker_task.cancel()
        self.revisit_worker_task = asyncio.create_task(self._revisit_worker())

        # Final check/warning for scope
        if not self.effective_scope:
            ctx.log.warn(
                "REMINDER: No target scope set via '--set nc_scope=...'. Nightcrawler workers started but will remain idle."
            )
        else:
            ctx.log.info("Background workers started/restarted.")

    async def done(self):
        """Hook called on mitmproxy shutdown for resource cleanup."""
        ctx.log.info("Main Addon: Shutting down...")
        # Safely cancel background worker tasks
        tasks_to_cancel: list[asyncio.Task] = []
        if self.scan_worker_task and not self.scan_worker_task.done():
            self.scan_worker_task.cancel()
            tasks_to_cancel.append(self.scan_worker_task)
        if self.crawl_worker_task and not self.crawl_worker_task.done():
            self.crawl_worker_task.cancel()
            tasks_to_cancel.append(self.crawl_worker_task)
        if self.revisit_worker_task and not self.revisit_worker_task.done():
            self.revisit_worker_task.cancel()
            tasks_to_cancel.append(self.revisit_worker_task)

        if tasks_to_cancel:
            ctx.log.debug(
                f"Waiting for {len(tasks_to_cancel)} worker task(s) to cancel..."
            )
            try:
                await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
                ctx.log.info("Worker tasks cancelled.")
            except asyncio.CancelledError:
                ctx.log.debug("Gather was cancelled (expected during shutdown).")
            except Exception as e:
                ctx.log.warn(f"Exception during worker task cancellation: {e}")

        # Close the shared httpx client
        if self.http_client:
            ctx.log.debug("Closing shared HTTP client...")
            try:
                await self.http_client.aclose()
                ctx.log.info("Shared HTTP client closed.")
            except Exception as e:
                ctx.log.warn(f"Exception while closing HTTP client: {e}")
            finally:
                self.http_client = None  # Clear reference
        ctx.log.info("Main Addon: Shutdown complete.")

    # --- Method to Register Injected Payloads ---
    def register_injection(self, probe_id: str, injection_details: Dict[str, Any]):
        """Registers details about an injected payload for Stored XSS checks."""
        if not probe_id:
            return
        details = injection_details.copy()
        details["timestamp"] = time.time()
        self.injected_payloads[probe_id] = details
        ctx.log.debug(
            f"[Injection Tracking] Registered probe {probe_id} from {details.get('url')}, param '{details.get('param_name')}' (Total tracked: {len(self.injected_payloads)})"
        )

    # --- Method to Check Responses for Stored Payloads ---
    def check_response_for_stored_payloads(
        self, response_text: Optional[str], current_url: str
    ):
        """Checks if any tracked payloads appear in the given response text."""
        if not response_text or not self.injected_payloads:
            return  # Nothing to check or no payloads tracked

        found_payload_ids = []
        # Check against the specific format used during injection
        payload_format_used = self.xss_stored_format
        if "{probe_id}" not in payload_format_used:
            # Avoid errors if format is misconfigured (already warned in configure)
            return

        # Iterate over a copy of keys in case cleanup happens concurrently (less likely here)
        payload_ids_to_check = list(self.injected_payloads.keys())

        for probe_id in payload_ids_to_check:
            # Check if the unique payload exists in the response text
            payload_to_find = payload_format_used.format(probe_id=probe_id)

            if payload_to_find in response_text:
                # Basic check passed, log potential finding
                injection_info = self.injected_payloads.get(probe_id, {})
                ctx.log.error(
                    f"[STORED XSS? FOUND] Probe ID: {probe_id} "
                    f"(Injected at: {injection_info.get('url')} / Param: '{injection_info.get('param_name')}') "
                    f"FOUND at URL: {current_url}"
                )
                found_payload_ids.append(probe_id)
                # TODO: Implement better reporting/state update (e.g., mark as found)

        # --- Cleanup Old Payloads by Age ---
        # Run cleanup periodically (e.g., every time this check runs on any response)
        current_time = time.time()
        max_age = self.payload_max_age  # Use configured value stored in self

        # Find payloads older than max_age
        ids_to_remove = {
            pid
            for pid, details in self.injected_payloads.items()
            if current_time - details.get("timestamp", 0) > max_age
        }
        if ids_to_remove:
            ctx.log.debug(
                f"Cleaning up {len(ids_to_remove)} tracked payloads older than {max_age}s."
            )
            for pid in ids_to_remove:
                self.injected_payloads.pop(pid, None)  # Use pop for safe removal

    # --- HTTP Hooks (request, response) ---
    def request(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted client requests."""
        # Check scope using the processed 'self.effective_scope' set
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return

        url = flow.request.pretty_url
        # Add manually visited URLs to the global discovered set
        if url not in self.discovered_urls:
            ctx.log.info(f"[DISCOVERY] Added URL (from Browse): {url}")
            self.discovered_urls.add(url)

        # Check if the request is a potential target for active scanning
        target_signature = create_target_signature(flow.request)
        # Queue for scanning only if signature is valid and not already scanned
        if target_signature and target_signature not in self.scanned_targets:
            self.scanned_targets.add(target_signature)
            # Prepare necessary details for the scan task
            scan_details = {
                "url": url,
                "method": flow.request.method,
                "params": dict(flow.request.query or {}),
                "data": dict(
                    flow.request.urlencoded_form or {}
                ),  # Only urlencoded forms for now
                "headers": dict(flow.request.headers),  # Copy headers
                "cookies": dict(flow.request.cookies or {}),  # Copy cookies
            }
            # Add to scan queue for background processing
            self.scan_queue.put_nowait(scan_details)
            ctx.log.debug(
                f"[SCAN QUEUE] Add Target: {target_signature} (Qsize: {self.scan_queue.qsize()})"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Processes intercepted server responses."""
        # Check scope using 'self.effective_scope'
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return

        # 1. Run passive checks on the response
        run_all_passive_checks(flow)  # Calls function from passive_scanner.py

        # 2. Parse for crawl links if HTML and successful response
        content_type = flow.response.headers.get("Content-Type", "")
        if (
            200 <= flow.response.status_code < 300
            and "html" in content_type
            and flow.response.text
        ):
            # ctx.log.debug(f"Response from {flow.request.pretty_url} is HTML, parsing links...") # Verbose
            # Call the imported function from crawler.py, passing necessary state
            parse_and_queue_links(
                flow.response.text,
                flow.request.pretty_url,
                self.discovered_urls,  # Pass the set of discovered URLs
                self.crawl_queue,  # Pass the crawl queue
                self.effective_scope,  # Pass the processed scope set
            )

        # 3. Check this response for *previously injected* stored payloads
        #    (Covers Browse traffic and potentially crawler traffic if hooks were modified)
        self.check_response_for_stored_payloads(
            flow.response.text, flow.request.pretty_url
        )

    # --- Background Workers (_crawl_worker, _scan_worker, _revisit_worker) ---

    async def _crawl_worker(self):
        """Asynchronous worker that processes the crawl queue."""
        ctx.log.info("Internal Crawl Worker started.")
        while True:
            # Wait until shared resources are ready
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            try:
                # ctx.log.debug("[CRAWL WORKER] Waiting for URL from queue...") # Verbose
                url_to_crawl = await self.crawl_queue.get()
                ctx.log.debug(
                    f"[CRAWL WORKER] Got URL: {url_to_crawl}. Waiting for semaphore..."
                )
                async with self.semaphore:  # Limit concurrent requests
                    ctx.log.debug(
                        f"[CRAWL WORKER] Semaphore acquired for {url_to_crawl}. Starting GET..."
                    )
                    try:
                        response = await self.http_client.get(url_to_crawl)
                        ctx.log.debug(
                            f"[CRAWLER TASK] Visited {url_to_crawl}, Status: {response.status_code}."
                        )

                        # Check crawler response for stored payloads
                        self.check_response_for_stored_payloads(
                            response.text, url_to_crawl
                        )

                        # Optionally parse response for more links (careful with depth/loops)
                        # content_type = response.headers.get("Content-Type", "")
                        # if 200 <= response.status_code < 300 and "html" in content_type and response.text:
                        #    parse_and_queue_links(response.text, str(response.url), self.discovered_urls, self.crawl_queue, self.effective_scope)

                    except httpx.TimeoutException:
                        ctx.log.warn(f"[CRAWLER TASK] Timeout visiting {url_to_crawl}")
                    except Exception as e:
                        ctx.log.warn(
                            f"[CRAWLER TASK] Error visiting {url_to_crawl}: {e}"
                        )
                    # finally: Semaphore released automatically

                self.crawl_queue.task_done()  # Mark task as done *after* semaphore released
            except asyncio.CancelledError:
                ctx.log.info("Crawl worker cancelled.")
                break  # Exit the while loop
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Crawl Worker loop: {e}")
                await asyncio.sleep(10)  # Prevent rapid looping on critical error

    async def _scan_worker(self):
        """Asynchronous worker that processes the active scan queue."""
        ctx.log.info("Internal Scan Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue  # Wait for init
            try:
                # ctx.log.debug("[SCAN WORKER] Waiting for target from queue...") # Verbose
                scan_details = await self.scan_queue.get()
                target_url_short = scan_details.get("url", "N/A").split("?")[0]
                # ctx.log.debug(f"[SCAN WORKER] Got target: {scan_details.get('method')} {target_url_short}. Waiting for semaphore...") # Verbose
                async with self.semaphore:  # Limit concurrent scan tasks
                    ctx.log.debug(
                        f"[SCAN WORKER] Starting scans for {target_url_short}..."
                    )
                    try:
                        cookies = scan_details.get("cookies", {})
                        target_method = scan_details.get("method", "GET").upper()

                        # --- Call Scan Functions Passing Configured Values ---
                        # Ensure HTTP client is ready before calling scanners
                        if not self.http_client:
                            ctx.log.warn(
                                f"[SCAN WORKER] HTTP client not ready, skipping scan for {target_url_short}"
                            )
                            continue

                        # 1. Basic SQLi Scan (pass loaded payloads from self.sqli_payloads)
                        await scan_sqli_basic(
                            scan_details, cookies, self.http_client, self.sqli_payloads
                        )

                        # 2. Basic Reflected XSS Scan (pass loaded payloads from self.xss_reflected_payloads)
                        await scan_xss_reflected_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.xss_reflected_payloads,
                        )

                        # 3. Stored XSS Injection (pass self for state + configured prefix/format from self.*)
                        await scan_xss_stored_inject(
                            scan_details,
                            cookies,
                            self.http_client,
                            self,
                            self.xss_stored_prefix,
                            self.xss_stored_format,
                        )

                        # --- Trigger Revisit Check ---
                        # If the request might have stored data, queue its URL for the revisit worker
                        if target_method in ["POST", "PUT", "PATCH"]:
                            revisit_url = scan_details["url"]
                            # Basic check to avoid immediate duplicates in revisit queue
                            # This check is not perfectly thread-safe but reduces noise
                            # A set could be used for faster checking if queue gets huge.
                            if revisit_url not in list(self.revisit_queue._queue):
                                ctx.log.debug(
                                    f"[Revisit Queue] Adding {revisit_url} post-injection. Qsize: {self.revisit_queue.qsize()}"
                                )
                                self.revisit_queue.put_nowait(revisit_url)

                        ctx.log.debug(
                            f"[SCAN WORKER] Scans finished for {target_url_short}."
                        )
                    except Exception as e:
                        # Log errors specific to scanning this particular target
                        ctx.log.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                    # finally: Semaphore released automatically

                self.scan_queue.task_done()  # Mark task as done *after* semaphore released
            except asyncio.CancelledError:
                ctx.log.info("Scan worker cancelled.")
                break  # Exit loop
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Scan Worker loop: {e}")
                await asyncio.sleep(10)  # Prevent rapid looping

    async def _revisit_worker(self):
        """Asynchronous worker that revisits URLs to check for stored payloads."""
        ctx.log.info("Internal Revisit Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue  # Wait for init
            try:
                # ctx.log.debug("[Revisit Worker] Waiting for URL from queue...") # Verbose
                url_to_revisit = await self.revisit_queue.get()
                ctx.log.debug(
                    f"[Revisit Worker] Got URL: {url_to_revisit}. Waiting for semaphore..."
                )
                async with self.semaphore:  # Share semaphore with other workers
                    # ctx.log.debug(f"[Revisit Worker] Semaphore acquired for {url_to_revisit}. Fetching page...") # Verbose
                    try:
                        # Use GET by default for revisiting.
                        # Consider passing original cookies? Complex state needed.
                        response = await self.http_client.get(url_to_revisit)
                        ctx.log.debug(
                            f"[Revisit Worker] Fetched {url_to_revisit}, Status: {response.status_code}. Checking for stored payloads..."
                        )
                        # Call the checking function using self.check_response...
                        self.check_response_for_stored_payloads(
                            response.text, url_to_revisit
                        )
                    except httpx.TimeoutException:
                        ctx.log.warn(
                            f"[Revisit Worker] Timeout fetching {url_to_revisit}"
                        )
                    except Exception as e:
                        ctx.log.warn(
                            f"[Revisit Worker] Error fetching {url_to_revisit}: {e}"
                        )
                    # finally: Semaphore released automatically

                self.revisit_queue.task_done()  # Mark task as done *after* semaphore released
            except asyncio.CancelledError:
                ctx.log.info("Revisit worker cancelled.")
                break  # Exit loop
            except Exception as e:
                ctx.log.critical(f"CRITICAL ERROR in Revisit Worker loop: {e}")
                await asyncio.sleep(10)  # Prevent rapid looping


# --- Addon Registration ---
# This instance gets loaded by mitmproxy. __init__ runs first, then mitmproxy calls hooks.
addons = [MainAddon()]
