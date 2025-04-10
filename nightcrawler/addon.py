# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import sys
import asyncio
import httpx
import time
import pathlib  # Needed for output file path and payload loading
import random  # Needed for payload ID generation
import json  # Added for JSONL output
import datetime  # Added for timestamp
import html  # For escaping HTML in report
import logging  # Added for fallback logging if ctx not ready
import traceback
import os  # Needed for path expansion and env vars
import yaml  # Needed for YAML config loading
from typing import Set, Dict, Any, Optional, List, TYPE_CHECKING

# --- Imports from local package modules ---
try:
    # config.py is now minimal or empty for user settings
    from nightcrawler.utils import is_in_scope, create_target_signature

    # Import the orchestrator function
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import parse_and_queue_links
    from nightcrawler.sqli_scanner import scan_sqli_basic

    # Import both XSS scanning functions
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

    # Import package version
    from nightcrawler import __version__ as nightcrawler_version
except ImportError as e:
    # Use standard logging here as ctx might not be available
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
DEFAULT_XSS_STORED_FORMAT = "<!-- {probe_id} -->"
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_USER_AGENT = f"Nightcrawler-MITM/{nightcrawler_version}"
DEFAULT_PAYLOAD_MAX_AGE = 3600  # 1 hour


def _get_default_config_dir() -> pathlib.Path:
    """Gets the default config directory path based on XDG standards."""
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return pathlib.Path(xdg_config_home) / "nightcrawler-mitm"
    else:
        # Fallback for non-XDG systems (e.g., Windows, or if var not set)
        return pathlib.Path.home() / ".config" / "nightcrawler-mitm"


def _get_default_data_dir() -> pathlib.Path:
    """Gets the default data directory path based on XDG standards."""
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return pathlib.Path(xdg_data_home) / "nightcrawler-mitm"
    else:
        # Fallback for non-XDG systems
        return pathlib.Path.home() / ".local" / "share" / "nightcrawler-mitm"


DEFAULT_CONFIG_FILE_PATH = _get_default_config_dir() / "config.yaml"
DEFAULT_DATA_DIR_PATH = _get_default_data_dir()


class MainAddon:
    """
    Main mitmproxy addon orchestrating background security tasks.
    Configuration via --set options. Logs findings to console and optionally JSONL file.
    """

    def __init__(self):
        """Initializes the addon's state."""
        self.discovered_urls: Set[str] = set()
        self.scanned_targets: Set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.revisit_queue: asyncio.Queue = asyncio.Queue()
        self.injected_payloads: Dict[str, Dict[str, Any]] = {}
        self.revisit_in_progress: Set[str] = set()
        self.websocket_hosts_logged: Set[str] = set()
        self.report_findings: List[Dict[str, Any]] = []

        self.semaphore: Optional[asyncio.Semaphore] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        self.revisit_worker_task: Optional[asyncio.Task] = None

        self.effective_scope: Set[str] = set()

        # --- Config values (initialized with code defaults, updated in 'configure') ---
        self.effective_scope: Set[str] = set()
        self.max_concurrency: int = DEFAULT_MAX_CONCURRENCY
        self.user_agent: str = DEFAULT_USER_AGENT
        self.payload_max_age: int = DEFAULT_PAYLOAD_MAX_AGE
        self.sqli_payloads: List[str] = DEFAULT_SQLI_PAYLOADS
        self.xss_reflected_payloads: List[str] = DEFAULT_XSS_REFLECTED_PAYLOADS
        self.xss_stored_prefix: str = DEFAULT_XSS_STORED_PREFIX
        self.xss_stored_format: str = DEFAULT_XSS_STORED_FORMAT
        self.output_filepath: Optional[pathlib.Path] = (
            None  # Final absolute path for JSONL
        )
        self.html_report_filepath: Optional[pathlib.Path] = (
            None  # Final absolute path for HTML
        )
        self.inspect_websocket: bool = False  # Default for the bool option

        # --- Internal Flags ---
        self.loaded_config: Dict = {}  # Parsed config file content
        self._output_file_error_logged: bool = False
        self._configured_once: bool = False

    def load(self, loader: addonmanager.Loader):
        """Define addon options using 'typespec' argument."""
        loader.add_option(
            name="nc_config",
            typespec=str,
            default=str(DEFAULT_CONFIG_FILE_PATH),  # Default path as string
            help=f"Path to the Nightcrawler YAML configuration file (Default: {DEFAULT_CONFIG_FILE_PATH}).",
        )
        loader.add_option(
            name="nc_scope",
            typespec=str,  # Use typespec
            default="",
            help="REQUIRED: Target scope domain(s), comma-separated.",
        )
        loader.add_option(
            name="nc_max_concurrency",
            typespec=int,  # Use typespec
            default=DEFAULT_MAX_CONCURRENCY,
            help=f"Max concurrent tasks (Default: {DEFAULT_MAX_CONCURRENCY}).",
        )
        loader.add_option(
            name="nc_user_agent",
            typespec=str,  # Use typespec
            default=DEFAULT_USER_AGENT,
            help=f"User-Agent for workers (Default: '{DEFAULT_USER_AGENT}').",
        )
        loader.add_option(
            name="nc_payload_max_age",
            typespec=int,  # Use typespec
            default=DEFAULT_PAYLOAD_MAX_AGE,
            help=f"Max age (s) for tracked payloads (Default: {DEFAULT_PAYLOAD_MAX_AGE}).",
        )
        loader.add_option(
            name="nc_sqli_payload_file",
            typespec=str,  # Use typespec
            default="",
            help="File with SQLi payloads (overrides defaults).",
        )
        loader.add_option(
            name="nc_xss_reflected_payload_file",
            typespec=str,  # Use typespec
            default="",
            help="File with Reflected XSS payloads (overrides defaults).",
        )
        loader.add_option(
            name="nc_xss_stored_prefix",
            typespec=str,  # Use typespec
            default=DEFAULT_XSS_STORED_PREFIX,
            help=f"Prefix for Stored XSS probes (Default: '{DEFAULT_XSS_STORED_PREFIX}').",
        )
        loader.add_option(
            name="nc_xss_stored_format",
            typespec=str,  # Use typespec
            default=DEFAULT_XSS_STORED_FORMAT,
            help=f"Format for Stored XSS probe ('{{probe_id}}') (Default: '{DEFAULT_XSS_STORED_FORMAT}').",
        )
        loader.add_option(
            name="nc_output_file",
            typespec=str,  # Use typespec
            default="",
            help="File path to save findings in JSONL format.",
        )
        loader.add_option(
            name="nc_inspect_websocket",
            typespec=bool,  # Tipo booleano
            default=False,  # Default: non ispezionare i messaggi
            help="Enable detailed logging of individual WebSocket messages.",
        )
        loader.add_option(
            name="nc_output_html",
            typespec=str,  # Expecting a filepath string
            default="",  # Default is disabled
            help="File path to save findings summary in HTML format (e.g., report.html).",
        )

    def configure(self, updated: Set[str]):
        """Process options using precedence: Defaults < Config File < --set."""
        ctx.log.debug(f"Configure hook called, processing updated options: {updated}")
        is_initial_config = not self._configured_once

        # --- 1. Load Config File ---
        if "nc_config" in updated or is_initial_config:
            config_file_path_str = ctx.options.nc_config
            try:
                config_file_path = (
                    pathlib.Path(config_file_path_str).expanduser().resolve()
                )
                if config_file_path.is_file():
                    ctx.log.info(f"Loading configuration from: {config_file_path}")
                    with open(config_file_path, "r", encoding="utf-8") as f:
                        self.loaded_config = (
                            yaml.safe_load(f) or {}
                        )  # Load YAML, default to empty dict if file is empty
                    if not isinstance(self.loaded_config, dict):
                        ctx.log.warn(
                            f"Config file '{config_file_path}' is not a valid dictionary. Ignoring."
                        )
                        self.loaded_config = {}
                else:
                    # Only warn if the user specified a path explicitly and it wasn't found
                    if config_file_path_str != str(DEFAULT_CONFIG_FILE_PATH):
                        ctx.log.warn(
                            f"Specified config file not found: {config_file_path}. Using defaults / --set values."
                        )
                    # Else, it's normal not to find the default config file on first run
                    self.loaded_config = {}
            except (yaml.YAMLError, OSError, Exception) as e:
                ctx.log.error(
                    f"Error loading config file '{config_file_path_str}': {e}. Using defaults / --set values."
                )
                self.loaded_config = {}

        # --- 2. Determine Effective Config for Each Option (Default < Config File < --set) ---
        # Helper to get final value based on precedence
        def get_effective_value(option_name: str, code_default: Any):
            config_file_value = self.loaded_config.get(
                option_name
            )  # Value from YAML file
            mitm_option_value = getattr(
                ctx.options, option_name
            )  # Value from mitmproxy (includes --set and load() default)
            load_hook_default = (
                code_default  # Assuming code default matches load() default
            )

            # Check if --set was likely used (value differs from load() default)
            if mitm_option_value != load_hook_default:
                final_value = mitm_option_value  # --set overrides everything
                source = "--set"
            elif config_file_value is not None:
                final_value = config_file_value  # Config file overrides code default
                source = "config file"
            else:
                final_value = code_default  # Use hardcoded default
                source = "default"

            # Perform type validation/conversion based on expected type
            expected_type = type(code_default)
            validated_value = final_value
            try:
                if expected_type == int:
                    validated_value = int(final_value)
                elif expected_type == str:
                    validated_value = str(final_value)
                elif expected_type == bool:  # Handle bool conversion robustly
                    if isinstance(final_value, str):
                        validated_value = final_value.lower() in [
                            "true",
                            "1",
                            "t",
                            "y",
                            "yes",
                        ]
                    else:
                        validated_value = bool(final_value)
                # Add more types if needed
            except (ValueError, TypeError) as e:
                ctx.log.warn(
                    f"Invalid value type '{final_value}' for option '{option_name}' ({source}). Using default '{code_default}'. Error: {e}"
                )
                validated_value = code_default

            # Apply specific constraints (e.g., min value)
            if option_name == "nc_max_concurrency":
                validated_value = max(1, validated_value)
            if option_name == "nc_payload_max_age":
                validated_value = max(60, validated_value)
            # Validate format string
            if (
                option_name == "nc_xss_stored_format"
                and "{probe_id}" not in validated_value
            ):
                ctx.log.warn(
                    f"Invalid value '{validated_value}' for '{option_name}' ({source}). Missing '{{probe_id}}'. Using default '{code_default}'."
                )
                validated_value = code_default

            # Log the source only if debugging or if it changed
            # ctx.log.debug(f"Effective value for {option_name}: '{validated_value}' (Source: {source})")
            return validated_value

        # Apply precedence for all options
        self.effective_scope = {
            s.strip()
            for s in get_effective_value("nc_scope", "").split(",")
            if s.strip()
        }
        self.max_concurrency = get_effective_value(
            "nc_max_concurrency", DEFAULT_MAX_CONCURRENCY
        )
        self.user_agent = get_effective_value("nc_user_agent", DEFAULT_USER_AGENT)
        self.payload_max_age = get_effective_value(
            "nc_payload_max_age", DEFAULT_PAYLOAD_MAX_AGE
        )
        self.xss_stored_prefix = get_effective_value(
            "nc_xss_stored_prefix", DEFAULT_XSS_STORED_PREFIX
        )
        self.xss_stored_format = get_effective_value(
            "nc_xss_stored_format", DEFAULT_XSS_STORED_FORMAT
        )
        self.inspect_websocket = get_effective_value(
            "nc_inspect_websocket", False
        )  # Bool default is False

        # Handle file paths separately for loading payloads / resolving output paths
        sqli_payload_file_path = get_effective_value("nc_sqli_payload_file", "")
        self.sqli_payloads = self._load_payloads_from_file(
            sqli_payload_file_path, DEFAULT_SQLI_PAYLOADS, "SQLi"
        )

        xss_refl_payload_file_path = get_effective_value(
            "nc_xss_reflected_payload_file", ""
        )
        self.xss_reflected_payloads = self._load_payloads_from_file(
            xss_refl_payload_file_path, DEFAULT_XSS_REFLECTED_PAYLOADS, "Reflected XSS"
        )

        # Handle output file paths (resolve relative paths)
        output_file_rel = get_effective_value("nc_output_file", "")
        self.output_filepath = self._resolve_output_path(
            output_file_rel, "findings JSONL"
        )

        output_html_rel = get_effective_value("nc_output_html", "")
        self.html_report_filepath = self._resolve_output_path(
            output_html_rel, "HTML report"
        )

        # Log final effective values
        ctx.log.info(f"Effective Scope: {self.effective_scope or 'None (Idle)'}")
        ctx.log.info(f"Effective Max Concurrency: {self.max_concurrency}")
        # Log other important final values as needed

        # THIS MUST BE THE LAST LINE :-)
        self._configured_once = True

    def _resolve_output_path(
        self, path_option_value: str, file_type: str
    ) -> Optional[pathlib.Path]:
        """Resolves relative paths against default data dir, ensures writability."""
        if not path_option_value:
            # ctx.log.info(f"{file_type} output disabled.")
            return None
        try:
            path = pathlib.Path(path_option_value)
            # If path is not absolute, resolve it relative to the default data directory
            if not path.is_absolute():
                data_dir = _get_default_data_dir()
                path = data_dir / path
                ctx.log.debug(f"Resolved relative {file_type} path to: {path}")

            # Ensure parent directory exists and check writability
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(
                exist_ok=True
            )  # Create file or update timestamp, checks writability
            ctx.log.info(f"{file_type} will be saved to: {path}")
            return path
        except Exception as e:
            ctx.log.error(
                f"Cannot use/write to specified path '{path_option_value}' for {file_type}: {e}. Disabled."
            )
            return None

    def _load_payloads_from_file(
        self, filepath: str, default_payloads: List[str], payload_type: str
    ) -> List[str]:
        """Loads payloads from file, falls back to defaults."""
        # --- Logic unchanged ---
        if not filepath:
            return list(default_payloads)
        try:
            path = pathlib.Path(filepath).resolve()
            payloads = [
                line.strip()
                for line in path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not payloads:
                ctx.log.warn(f"Payload file '{path}' empty. Using defaults.")
                return list(default_payloads)
            ctx.log.info(f"Loaded {len(payloads)} {payload_type} payloads from: {path}")
            return payloads
        except FileNotFoundError:
            ctx.log.warn(f"Payload file '{filepath}' not found. Using defaults.")
            return list(default_payloads)
        except Exception as e:
            ctx.log.error(
                f"Error loading payload file '{filepath}': {e}. Using defaults."
            )
            return list(default_payloads)

    def _log_finding(
        self,
        level: str,
        finding_type: str,
        url: str,
        detail: str,
        evidence: Optional[Dict] = None,
    ):
        """Logs finding to console, optionally to JSONL file, and collects for HTML report."""
        # 1. Log to Console (using ctx.log)
        log_func = getattr(ctx.log, level.lower(), ctx.log.info)
        log_message = f"[{finding_type}] {detail} at {url}"
        if evidence:
            evidence_str = ", ".join(
                f"{k}={str(v)[:50]}" for k, v in evidence.items() if v is not None
            )
            log_message += f" (Evidence: {evidence_str})"
        try:
            log_func(log_message)
        except Exception as e:
            print(
                f"FALLBACK LOG ({level}): {log_message}\nLog err: {e}", file=sys.stderr
            )

        # Prepare structured data (used for both JSONL and HTML report)
        finding_data = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": level.upper(),
            "type": finding_type,
            "url": url,
            "detail": detail,
            "evidence": evidence if evidence is not None else {},
        }

        # 2. Log to JSONL file if configured
        if self.output_filepath:
            try:
                with open(self.output_filepath, "a", encoding="utf-8") as f:
                    json.dump(finding_data, f, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:
                if not self._output_file_error_logged:
                    ctx.log.error(
                        f"Failed write to JSONL '{self.output_filepath}': {e}"
                    )
                    self._output_file_error_logged = True

        if self.html_report_filepath:
            self.report_findings.append(finding_data)

    def _generate_html_report(self):
        """Generates a simple HTML report from collected findings."""
        if not self.html_report_filepath or not self.report_findings:
            ctx.log.debug("HTML report disabled or no findings to report.")
            return

        ctx.log.info(f"Generating HTML report at: {self.html_report_filepath}")
        start_time = time.time()

        # Sort findings (e.g., by severity then URL)
        # Define severity order for sorting
        severity_order = {"ERROR": 0, "WARN": 1, "INFO": 2}
        sorted_findings = sorted(
            self.report_findings,
            key=lambda x: (
                severity_order.get(x.get("level", "INFO"), 99),
                x.get("url", ""),
            ),
        )

        # Basic HTML structure with embedded CSS
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nightcrawler Scan Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        pre {{ background-color: #eee; padding: 5px; border: 1px solid #ccc; white-space: pre-wrap; word-wrap: break-word; margin: 0; font-size: 0.85em; }}
        .level-ERROR {{ color: red; font-weight: bold; }}
        .level-WARN {{ color: orange; font-weight: bold; }}
        .level-INFO {{ color: blue; }}
        .evidence-key {{ font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Nightcrawler Scan Report</h1>
    <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <h2>Summary</h2>
    <p>Total Findings: {len(sorted_findings)}</p>
    <h2>Findings Details</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp (UTC)</th>
                <th>Level</th>
                <th>Type</th>
                <th>URL / Context</th>
                <th>Detail</th>
                <th>Evidence</th>
            </tr>
        </thead>
        <tbody>
"""
        # Add table rows for each finding
        for finding in sorted_findings:
            ts = finding.get("timestamp", "N/A")
            level = finding.get("level", "INFO")
            ftype = finding.get("type", "N/A")
            url = finding.get("url", "N/A")
            detail = finding.get("detail", "")
            evidence = finding.get("evidence", {})

            # Escape HTML special characters in data
            ts_esc = html.escape(ts)
            level_esc = html.escape(level)
            ftype_esc = html.escape(ftype)
            url_esc = html.escape(url)
            detail_esc = html.escape(detail)

            # Format evidence nicely
            evidence_html = ""
            if evidence:
                evidence_items = []
                for k, v in evidence.items():
                    # Simple formatting, could be improved (e.g., handle nested dicts/lists)
                    evidence_items.append(
                        f'<div><span class="evidence-key">{html.escape(k)}:</span> <pre>{html.escape(str(v))}</pre></div>'
                    )
                evidence_html = "\n".join(evidence_items)
            else:
                evidence_html = "N/A"

            html_content += f"""
            <tr>
                <td>{ts_esc}</td>
                <td class="level-{level_esc}">{level_esc}</td>
                <td>{ftype_esc}</td>
                <td><pre>{url_esc}</pre></td>
                <td>{detail_esc}</td>
                <td>{evidence_html}</td>
            </tr>
"""

        # Close HTML structure
        html_content += """
        </tbody>
    </table>
</body>
</html>
"""
        # Write the HTML content to the file
        try:
            with open(self.html_report_filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
            elapsed = time.time() - start_time
            ctx.log.info(
                f"HTML report generated successfully in {elapsed:.2f} seconds."
            )
        except Exception as e:
            ctx.log.error(
                f"Failed to write HTML report to '{self.html_report_filepath}': {e}"
            )

    # --- END of HTML report generation method ---

    def running(self):
        """Initialize resources and start workers."""
        # --- Logic unchanged ---
        try:
            version = nightcrawler_version
        except NameError:
            version = "unknown"
        ctx.log.info("=" * 30)
        ctx.log.info(f" Nightcrawler Addon v{version} Running... ")
        ctx.log.info("=" * 30)
        ctx.log.info(f"Effective Scope: {self.effective_scope or 'Not Set (Idle)'}")
        if not self.semaphore or self.semaphore._value != self.max_concurrency:
            self.semaphore = asyncio.Semaphore(self.max_concurrency)
            ctx.log.debug(f"Semaphore init (concurrency {self.max_concurrency})")
        if (
            not self.http_client
            or self.http_client.headers.get("User-Agent") != self.user_agent
        ):
            if self.http_client:
                asyncio.create_task(self.http_client.aclose())
            self.http_client = httpx.AsyncClient(
                headers={"User-Agent": self.user_agent},
                verify=False,
                timeout=15.0,
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=self.max_concurrency + 10,
                    max_keepalive_connections=self.max_concurrency,
                ),
            )
            ctx.log.debug(f"HTTP Client init (UA: {self.user_agent})")
        tasks_to_start = []
        if not self.crawl_worker_task or self.crawl_worker_task.done():
            tasks_to_start.append(("_crawl_worker_task", self._crawl_worker))
        if not self.scan_worker_task or self.scan_worker_task.done():
            tasks_to_start.append(("_scan_worker_task", self._scan_worker))
        if not self.revisit_worker_task or self.revisit_worker_task.done():
            tasks_to_start.append(("_revisit_worker_task", self._revisit_worker))
        for task_attr, worker_func in tasks_to_start:
            prev_task = getattr(self, task_attr, None)
            if prev_task and not prev_task.done():
                prev_task.cancel()
            setattr(self, task_attr, asyncio.create_task(worker_func()))
        if not self.effective_scope:
            ctx.log.warn("REMINDER: No target scope set via '--set nc_scope=...'.")
        else:
            ctx.log.info("Background workers started/verified.")

    async def done(self):
        """Hook called on mitmproxy shutdown for resource cleanup."""
        ctx.log.info("Main Addon: Shutting down...")
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
                ctx.log.debug("Gather cancelled (expected).")
            except Exception as e:
                ctx.log.warn(f"Exception during worker task cancellation: {e}")
        if self.http_client:
            await self.http_client.aclose()
            ctx.log.info("Shared HTTP client closed.")
            self.http_client = None

        self._generate_html_report()
        ctx.log.info("Main Addon: Shutdown complete.")

    # --- Method to Register Injected Payloads ---
    def register_injection(self, probe_id: str, injection_details: Dict[str, Any]):
        # --- Logic unchanged ---
        if not probe_id:
            return
        details = injection_details.copy()
        details["timestamp"] = time.time()
        self.injected_payloads[probe_id] = details
        ctx.log.debug(
            f"[Injection Tracking] Registered probe {probe_id} (Total: {len(self.injected_payloads)})"
        )

    # --- Method to Check Responses for Stored Payloads ---
    def check_response_for_stored_payloads(
        self, response_text: Optional[str], current_url: str
    ):
        # --- Logic unchanged, uses self.payload_max_age, self.xss_stored_format, self._log_finding ---
        if not response_text or not self.injected_payloads:
            return
        payload_format_used = self.xss_stored_format
        found_count = 0
        if "{probe_id}" not in payload_format_used:
            return
        payload_ids_to_check = list(self.injected_payloads.keys())
        for probe_id in payload_ids_to_check:
            payload_to_find = payload_format_used.format(probe_id=probe_id)
            if response_text.find(payload_to_find) != -1:
                injection_info = self.injected_payloads.get(probe_id, {})
                self._log_finding(
                    level="ERROR",
                    finding_type="Stored XSS? FOUND",
                    url=current_url,
                    detail=f"Probe ID: {probe_id} (Injected at: {injection_info.get('url')} / Param: '{injection_info.get('param_name')}')",
                    evidence={
                        "probe_id": probe_id,
                        "injection_url": injection_info.get("url"),
                        "injection_param": injection_info.get("param_name"),
                    },
                )
                found_count += 1
        # Cleanup logic
        current_time = time.time()
        max_age = self.payload_max_age
        ids_to_remove = {
            pid
            for pid, details in self.injected_payloads.items()
            if current_time - details.get("timestamp", 0) > max_age
        }
        if ids_to_remove:
            ctx.log.debug(
                f"Cleaning up {len(ids_to_remove)} tracked payloads older than {max_age}s."
            )
            [self.injected_payloads.pop(pid, None) for pid in ids_to_remove]

    # --- HTTP Hooks (request, response) ---
    def request(self, flow: http.HTTPFlow) -> None:
        # --- Logic unchanged ---
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return
        url = flow.request.pretty_url
        if url not in self.discovered_urls:
            ctx.log.info(f"[DISCOVERY] Added URL: {url}")
            self.discovered_urls.add(url)
        target_signature = create_target_signature(flow.request)

        # --- DEBUG LOGIC CORRETTA ---
        if target_signature:
            # A signature was generated (parameters were found)
            if target_signature not in self.scanned_targets:
                # Target is new, add to set and queue
                self.scanned_targets.add(target_signature)
                scan_details = {
                    "url": url,
                    "method": flow.request.method,
                    "params": dict(flow.request.query or {}),
                    "data": dict(flow.request.urlencoded_form or {}),
                    "headers": dict(flow.request.headers),
                    "cookies": dict(flow.request.cookies or {}),
                }
                self.scan_queue.put_nowait(scan_details)
                ctx.log.debug(
                    f"[SCAN QUEUE] Add Target: {target_signature} (Qsize: {self.scan_queue.qsize()})"
                )
            else:
                # Target signature found, but already in scanned_targets set
                ctx.log.debug(
                    f"[SCAN QUEUE] Skipping Target (already scanned): {target_signature}"
                )
        else:
            # No signature was generated (create_target_signature returned None)
            # This usually means no parameters were found for scanning
            # Log only once per URL to avoid noise if many parameter-less requests are made
            if url not in getattr(self, "_logged_no_sig_urls", set()):
                ctx.log.debug(
                    f"[SCAN QUEUE] No parameters found/signature generated for: {url}"
                )
                if not hasattr(self, "_logged_no_sig_urls"):
                    self._logged_no_sig_urls = set()
                self._logged_no_sig_urls.add(url)
            # -----------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        # --- Logic unchanged, calls run_all_passive_checks(flow, self) ---
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return
        try:
            run_all_passive_checks(flow, self)
        except Exception as e:
            ctx.log.error(f"Error in passive scans for {flow.request.pretty_url}: {e}")
        content_type = flow.response.headers.get("Content-Type", "")
        if (
            200 <= flow.response.status_code < 300
            and "html" in content_type
            and flow.response.text
        ):
            parse_and_queue_links(
                flow.response.text,
                flow.request.pretty_url,
                self.discovered_urls,
                self.crawl_queue,
                self.effective_scope,
            )
        self.check_response_for_stored_payloads(
            flow.response.text, flow.request.pretty_url
        )

    # --- Background Workers (_crawl_worker, _scan_worker, _revisit_worker) ---

    async def _crawl_worker(self):
        # --- Logic unchanged ---
        ctx.log.info("Internal Crawl Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            url_to_crawl = None
            try:
                url_to_crawl = await self.crawl_queue.get()
                async with self.semaphore:
                    try:
                        response = await self.http_client.get(url_to_crawl)
                        ctx.log.debug(
                            f"[CRAWLER TASK] Visited {url_to_crawl}, Status: {response.status_code}."
                        )
                        self.check_response_for_stored_payloads(
                            response.text, url_to_crawl
                        )
                    except httpx.TimeoutException:
                        ctx.log.warn(f"[CRAWLER TASK] Timeout visiting {url_to_crawl}")
                    except Exception as e:
                        ctx.log.warn(
                            f"[CRAWLER TASK] Error visiting {url_to_crawl}: {e}"
                        )
            except asyncio.CancelledError:
                ctx.log.info("Crawl worker cancelled.")
                break
            except Exception as e:
                ctx.log.error(f"CRITICAL ERROR in Crawl Worker loop: {e}")
                ctx.log.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if url_to_crawl:
                    self.crawl_queue.task_done()

    async def _scan_worker(self):
        """Asynchronous worker that processes the active scan queue."""
        ctx.log.info("Internal Scan Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            scan_details = None
            try:
                scan_details = await self.scan_queue.get()
                target_url_short = scan_details.get("url", "N/A").split("?")[0]
                async with self.semaphore:
                    ctx.log.debug(
                        f"[SCAN WORKER] Starting scans for {target_url_short}..."
                    )
                    try:
                        cookies = scan_details.get("cookies", {})
                        target_method = scan_details.get("method", "GET").upper()
                        if not self.http_client:
                            continue
                        await scan_sqli_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.sqli_payloads,
                            self,
                        )
                        await scan_xss_reflected_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.xss_reflected_payloads,
                            self,
                        )
                        await scan_xss_stored_inject(
                            scan_details,
                            cookies,
                            self.http_client,
                            self,
                            self.xss_stored_prefix,
                            self.xss_stored_format,
                        )
                        if target_method in ["POST", "PUT", "PATCH"]:
                            revisit_url = scan_details["url"]
                            if revisit_url not in self.revisit_in_progress:
                                self.revisit_in_progress.add(revisit_url)
                                self.revisit_queue.put_nowait(revisit_url)
                                ctx.log.debug(
                                    f"[Revisit Queue] Adding {revisit_url}. Qsize: {self.revisit_queue.qsize()}, InProgressSet: {len(self.revisit_in_progress)}"
                                )
                        ctx.log.debug(
                            f"[SCAN WORKER] Scans finished for {target_url_short}."
                        )
                    except Exception as e:
                        ctx.log.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                        ctx.log.error(traceback.format_exc())
            except asyncio.CancelledError:
                ctx.log.info("Scan worker cancelled.")
                break
            except Exception as e:
                ctx.log.error(f"CRITICAL ERROR in Scan Worker loop: {e}")
                ctx.log.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if scan_details:
                    self.scan_queue.task_done()

    async def _revisit_worker(self):
        # --- Logic unchanged ---
        ctx.log.info("Internal Revisit Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            url_to_revisit = None
            try:
                url_to_revisit = await self.revisit_queue.get()
                async with self.semaphore:
                    try:
                        if url_to_revisit not in self.revisit_in_progress:
                            ctx.log.debug(
                                f"[Revisit Worker] URL {url_to_revisit} no longer in progress set. Skipping."
                            )
                            continue
                        response = await self.http_client.get(url_to_revisit)
                        ctx.log.debug(
                            f"[Revisit Worker] Fetched {url_to_revisit}, Status: {response.status_code}. Checking..."
                        )
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
            except asyncio.CancelledError:
                ctx.log.info("Revisit worker cancelled.")
                break
            except Exception as e:
                ctx.log.error(f"CRITICAL ERROR in Revisit Worker loop: {e}")
                ctx.log.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if url_to_revisit:
                    self.revisit_in_progress.discard(url_to_revisit)
                    self.revisit_queue.task_done()

    # --- WEBSOCKET HOOKS (Now simplified wrappers) ---

    def websocket_start(self, flow: http.HTTPFlow):
        """Mitmproxy hook called when a WebSocket connection is established."""
        # Delegate to the handler function, passing self (the addon instance)
        handle_websocket_start(flow, self)

    def websocket_message(self, flow: http.HTTPFlow):
        """Mitmproxy hook called for each WebSocket message."""
        # Delegate to the handler function, passing self
        handle_websocket_message(flow, self)

    def websocket_error(self, flow: http.HTTPFlow):
        """Mitmproxy hook called on WebSocket errors."""
        # Delegate to the handler function, passing self
        handle_websocket_error(flow, self)

    def websocket_end(self, flow: http.HTTPFlow):
        """Mitmproxy hook called when a WebSocket connection ends."""
        # Delegate to the handler function, passing self
        handle_websocket_end(flow, self)

    # --- END WEBSOCKET HOOKS ---


# --- Addon Registration ---
addons = [MainAddon()]

# End of nightcrawler/addon.py
