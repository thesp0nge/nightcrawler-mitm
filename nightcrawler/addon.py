# nightcrawler/addon.py
import mitmproxy.http
from mitmproxy import ctx, http, addonmanager
import asyncio
import httpx
import time
import pathlib
import random
import json
import datetime
import logging
import traceback
import os
import yaml
import html
from typing import Set, Dict, Any, Optional, List, TYPE_CHECKING, Union
from urllib.parse import urlparse, urlunparse

# --- Imports from local package modules ---
try:
    from nightcrawler.config import *
    from nightcrawler.utils import is_in_scope, create_target_signature
    from nightcrawler.passive_scanner import run_all_passive_checks
    from nightcrawler.crawler import discover_and_queue_targets
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
    from nightcrawler.active_scans.traversal import scan_directory_traversal
    from nightcrawler import __version__ as nightcrawler_version
except ImportError as e:
    logging.basicConfig(level=logging.CRITICAL)
    logging.critical(f"CRITICAL ERROR: Cannot import required modules: {e}")
    raise ImportError(f"Local dependencies not found: {e}") from e

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


# --- Default Path Helpers (Correctly located in this file) ---
def get_default_config_dir() -> pathlib.Path:
    """Gets the default config directory path based on XDG Base Directory Specification."""
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home and os.path.isdir(xdg_config_home):
        return pathlib.Path(xdg_config_home) / "nightcrawler-mitm"
    else:
        return pathlib.Path.home() / ".config" / "nightcrawler-mitm"


def get_default_data_dir() -> pathlib.Path:
    """Gets the default data directory path based on XDG Base Directory Specification."""
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home and os.path.isdir(xdg_data_home):
        return pathlib.Path(xdg_data_home) / "nightcrawler-mitm"
    else:
        return pathlib.Path.home() / ".local" / "share" / "nightcrawler-mitm"


DEFAULT_CONFIG_FILE_PATH: pathlib.Path = get_default_config_dir() / "config.yaml"


class MainAddon:
    """Main mitmproxy addon orchestrating all Nightcrawler tasks."""

    def __init__(self):
        """Initializes the addon's state."""
        # State variables
        self.discovered_urls: set[str] = set()
        self.scanned_targets: set[str] = set()
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.crawl_queue: asyncio.Queue = asyncio.Queue()
        self.revisit_queue: asyncio.Queue = asyncio.Queue()
        self.discovery_queue: asyncio.Queue = asyncio.Queue()
        self.injected_payloads: dict[str, dict[str, Any]] = {}
        self.revisit_in_progress: set[str] = set()
        self.websocket_hosts_logged: set[str] = set()
        self.discovered_dirs: set[str] = set()
        self.report_findings: list[dict[str, Any]] = []

        # Resources and Flags
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.crawl_worker_task: Optional[asyncio.Task] = None
        self.scan_worker_task: Optional[asyncio.Task] = None
        self.revisit_worker_task: Optional[asyncio.Task] = None
        self.discovery_worker_task: Optional[asyncio.Task] = None
        self._output_file_error_logged: bool = False
        self.logger: Any = logging.getLogger("nightcrawler")  # Placeholder logger

    def load(self, loader: addonmanager.Loader):
        """Define all addon options."""
        loader.add_option(
            name="nc_config",
            typespec=str,
            default=str(DEFAULT_CONFIG_FILE_PATH),
            help="Path to config file.",
        )
        loader.add_option(
            name="nc_scope",
            typespec=str,
            default="",
            help="REQUIRED: Target scope domain(s).",
        )
        loader.add_option(
            name="nc_max_concurrency",
            typespec=int,
            default=DEFAULT_MAX_CONCURRENCY,
            help="Max concurrent tasks.",
        )
        loader.add_option(
            name="nc_user_agent",
            typespec=str,
            default=DEFAULT_USER_AGENT,
            help="User-Agent for workers.",
        )
        loader.add_option(
            name="nc_payload_max_age",
            typespec=int,
            default=DEFAULT_PAYLOAD_MAX_AGE,
            help="Max age (s) for tracked payloads.",
        )
        loader.add_option(
            name="nc_sqli_payload_file",
            typespec=str,
            default="",
            help="File with SQLi payloads.",
        )
        loader.add_option(
            name="nc_xss_reflected_payload_file",
            typespec=str,
            default="",
            help="File with Reflected XSS payloads.",
        )
        loader.add_option(
            name="nc_xss_stored_prefix",
            typespec=str,
            default=DEFAULT_XSS_STORED_PREFIX,
            help="Prefix for Stored XSS probes.",
        )
        loader.add_option(
            name="nc_xss_stored_format",
            typespec=str,
            default=DEFAULT_XSS_STORED_FORMAT,
            help="Format for Stored XSS probe.",
        )
        loader.add_option(
            name="nc_output_file",
            typespec=str,
            default="",
            help="File path for JSONL findings.",
        )
        loader.add_option(
            name="nc_output_html",
            typespec=str,
            default="",
            help="File path for HTML report.",
        )
        loader.add_option(
            name="nc_inspect_websocket",
            typespec=bool,
            default=False,
            help="Enable detailed WebSocket message logging.",
        )
        loader.add_option(
            name="nc_discovery_wordlist",
            typespec=str,
            default="",
            help="File path for discovery wordlist.",
        )

    def configure(self, updated: Set[str]):
        """Process options using precedence: --set > Config File > Defaults."""
        loaded_config = {}
        try:
            config_path = pathlib.Path(ctx.options.nc_config).expanduser().resolve()
            if config_path.is_file():
                self.logger.info(f"Loading configuration from: {config_path}")
                with open(config_path, "r", encoding="utf-8") as f:
                    loaded_config = yaml.safe_load(f) or {}
                if not isinstance(loaded_config, dict):
                    self.logger.warn(
                        f"Config file '{config_path}' is not a dict. Ignoring."
                    )
                    loaded_config = {}
        except Exception as e:
            self.logger.error(
                f"Error loading config file '{ctx.options.nc_config}': {e}"
            )

        def get_final_value(name: str):
            cli_or_default_val = getattr(ctx.options, name)
            if cli_or_default_val != ctx.options.default(name):
                return cli_or_default_val
            return loaded_config.get(name, cli_or_default_val)

        self.effective_scope = {
            s.strip() for s in get_final_value("nc_scope").split(",") if s.strip()
        }
        self.max_concurrency = max(1, int(get_final_value("nc_max_concurrency")))
        self.user_agent = get_final_value("nc_user_agent")
        self.payload_max_age = max(60, int(get_final_value("nc_payload_max_age")))
        self.inspect_websocket = bool(get_final_value("nc_inspect_websocket"))
        self.xss_stored_prefix = get_final_value("nc_xss_stored_prefix")
        self.xss_stored_format = get_final_value("nc_xss_stored_format")
        if "{probe_id}" not in self.xss_stored_format:
            self.logger.warn(
                f"Invalid nc_xss_stored_format: '{self.xss_stored_format}'. Reverting to default."
            )
            self.xss_stored_format = DEFAULT_XSS_STORED_FORMAT

        self.sqli_payloads = self._load_wordlist_list(
            get_final_value("nc_sqli_payload_file"), DEFAULT_SQLI_PAYLOADS, "SQLi"
        )
        self.xss_reflected_payloads = self._load_wordlist_list(
            get_final_value("nc_xss_reflected_payload_file"),
            DEFAULT_XSS_REFLECTED_PAYLOADS,
            "Reflected XSS",
        )
        self.discovery_wordlist = self._load_wordlist_set(
            get_final_value("nc_discovery_wordlist"),
            DEFAULT_DISCOVERY_WORDLIST,
            "Content Discovery",
        )

        self.output_filepath = self._resolve_output_path(
            get_final_value("nc_output_file"), "findings JSONL"
        )
        self.html_report_filepath = self._resolve_output_path(
            get_final_value("nc_output_html"), "HTML report"
        )

    def _load_wordlist_list(
        self, filepath: str, default_items: list[str], list_type: str
    ) -> list[str]:
        if not filepath:
            return list(default_items)
        try:
            path = pathlib.Path(filepath).expanduser().resolve()
            words = [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if not words:
                self.logger.warn(
                    f"File '{path}' for {list_type} empty. Using defaults."
                )
                return list(default_items)
            self.logger.info(f"Loaded {len(words)} items for {list_type} from: {path}")
            return words
        except Exception as e:
            self.logger.error(
                f"Error loading {list_type} file '{filepath}': {e}. Using defaults."
            )
            return list(default_items)

    def _load_wordlist_set(
        self, filepath: str, default_items: set[str], list_type: str
    ) -> set[str]:
        if not filepath:
            return set(default_items)
        try:
            path = pathlib.Path(filepath).expanduser().resolve()
            words = {
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
            if not words:
                self.logger.warn(
                    f"File '{path}' for {list_type} empty. Using defaults."
                )
                return set(default_items)
            self.logger.info(f"Loaded {len(words)} items for {list_type} from: {path}")
            return words
        except Exception as e:
            self.logger.error(
                f"Error loading {list_type} file '{filepath}': {e}. Using defaults."
            )
            return set(default_items)

    def _resolve_output_path(
        self, path_str: str, file_type: str
    ) -> Optional[pathlib.Path]:
        if not path_str:
            return None
        try:
            path = pathlib.Path(path_str).expanduser()
            if not path.is_absolute():
                path = get_default_data_dir() / path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
            self.logger.info(f"{file_type} will be saved to: {path}")
            return path
        except Exception as e:
            self.logger.error(
                f"Cannot use path '{path_str}' for {file_type}: {e}. Disabled."
            )
            return None

    def _log_finding(
        self,
        level: str,
        finding_type: str,
        url: str,
        detail: str,
        evidence: Optional[Dict] = None,
    ):
        log_func = getattr(self.logger, level.lower(), self.logger.info)
        log_message = f"[{finding_type}] {detail} at {url}"
        log_func(log_message)
        finding_data = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": level.upper(),
            "type": finding_type,
            "url": url,
            "detail": detail,
            "evidence": evidence or {},
        }
        if self.html_report_filepath:
            self.report_findings.append(finding_data)
        if self.output_filepath:
            try:
                with open(self.output_filepath, "a", encoding="utf-8") as f:
                    json.dump(finding_data, f, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:
                if not self._output_file_error_logged:
                    self.logger.error(f"Failed write to '{self.output_filepath}': {e}")
                    self._output_file_error_logged = True

    def _generate_html_report(self):
        if not self.html_report_filepath or not self.report_findings:
            if self.html_report_filepath:
                self.logger.info(
                    "HTML report enabled, but no findings were logged. Report file not created."
                )
            return
        self.logger.info(f"Generating HTML report at: {self.html_report_filepath}")
        severity_order = {"ERROR": 0, "WARN": 1, "INFO": 2}
        sorted_findings = sorted(
            self.report_findings,
            key=lambda x: (
                severity_order.get(x.get("level", "INFO"), 99),
                x.get("url", ""),
            ),
        )
        html_content = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Nightcrawler Scan Report</title>
<style>body{{font-family:sans-serif;margin:20px;}}h1,h2{{border-bottom:1px solid #ccc;}}table{{width:100%;border-collapse:collapse;font-size:0.9em;}}th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;}}th{{background-color:#f2f2f2;}}pre{{background-color:#eee;padding:5px;border:1px solid #ccc;white-space:pre-wrap;word-wrap:break-word;}}
.level-ERROR{{color:red;font-weight:bold;}}.level-WARN{{color:orange;font-weight:bold;}}.level-INFO{{color:blue;}}.evidence-key{{font-weight:bold;}}</style></head>
<body><h1>Nightcrawler Scan Report</h1><p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p><h2>Summary</h2><p>Total Findings: {len(sorted_findings)}</p>
<table><thead><tr><th>Timestamp (UTC)</th><th>Level</th><th>Type</th><th>URL/Context</th><th>Detail</th><th>Evidence</th></tr></thead><tbody>"""
        for finding in sorted_findings:
            ts, level, ftype, url, detail, evidence = (
                finding.get(k, "")
                for k in ["timestamp", "level", "type", "url", "detail", "evidence"]
            )
            evidence_html = (
                "\n".join(
                    [
                        f'<div><span class="evidence-key">{html.escape(k)}:</span> <pre>{html.escape(str(v))}</pre></div>'
                        for k, v in evidence.items()
                    ]
                )
                if evidence
                else "N/A"
            )
            html_content += f"""<tr><td>{html.escape(ts)}</td><td class="level-{html.escape(level)}">{html.escape(level)}</td><td>{html.escape(ftype)}</td><td><pre>{html.escape(url)}</pre></td><td>{html.escape(detail)}</td><td>{evidence_html}</td></tr>"""
        html_content += "</tbody></table></body></html>"
        try:
            with open(self.html_report_filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
            self.logger.info(f"HTML report generated successfully.")
        except Exception as e:
            self.logger.error(f"Failed to write HTML report: {e}")

    def running(self):
        self.logger = ctx.log
        self.logger.info("=" * 30)
        self.logger.info(f" Nightcrawler Addon v{nightcrawler_version} Running... ")
        self.logger.info("=" * 30)
        self.configure(set(ctx.options.keys()))
        self.logger.info(f"Effective Scope: {self.effective_scope or 'Not Set (Idle)'}")
        if not self.semaphore or self.semaphore._value != self.max_concurrency:
            self.semaphore = asyncio.Semaphore(self.max_concurrency)
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
                limits=httpx.Limits(max_connections=self.max_concurrency + 10),
            )
        tasks_to_start = [
            ("_crawl_worker_task", self._crawl_worker),
            ("_scan_worker_task", self._scan_worker),
            ("_revisit_worker_task", self._revisit_worker),
            ("_discovery_worker_task", self._discovery_worker),
        ]
        for task_attr, worker_func in tasks_to_start:
            prev_task = getattr(self, task_attr, None)
            if prev_task and not prev_task.done():
                prev_task.cancel()
            setattr(self, task_attr, asyncio.create_task(worker_func()))
        if not self.effective_scope:
            self.logger.warn("REMINDER: No target scope set via '--set nc_scope=...'.")
        else:
            self.logger.info("Background workers started/verified.")

    async def done(self):
        self.logger.info("Main Addon: Shutting down...")
        tasks_to_cancel = []
        worker_tasks = [
            self.scan_worker_task,
            self.crawl_worker_task,
            self.revisit_worker_task,
            self.discovery_worker_task,
        ]
        for task in worker_tasks:
            if task and not task.done():
                task.cancel()
                tasks_to_cancel.append(task)
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            self.logger.info("Worker tasks cancelled.")
        if self.http_client:
            await self.http_client.aclose()
            self.logger.info("Shared HTTP client closed.")
        self._generate_html_report()
        self.logger.info("Main Addon: Shutdown complete.")

    def request(self, flow: http.HTTPFlow):
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return
        url = flow.request.pretty_url
        if url not in self.discovered_urls:
            self.logger.info(f"[DISCOVERY] Added URL: {url}")
            self.discovered_urls.add(url)
        target_signature = create_target_signature(flow.request, self.logger)
        if target_signature and target_signature not in self.scanned_targets:
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
        try:
            parsed_url = urlparse(url)
            dir_path = os.path.dirname(parsed_url.path)
            if not dir_path.endswith("/"):
                dir_path += "/"
            base_dir_url = urlunparse(
                (parsed_url.scheme, parsed_url.netloc, dir_path, "", "", "")
            )
            if base_dir_url not in self.discovered_dirs:
                self.discovered_dirs.add(base_dir_url)
                self.discovery_queue.put_nowait(base_dir_url)
        except Exception as e:
            self.logger.debug(f"Could not extract directory from {url}: {e}")

    def response(self, flow: http.HTTPFlow):
        if not self.effective_scope or not is_in_scope(
            flow.request.pretty_url, self.effective_scope
        ):
            return
        try:
            run_all_passive_checks(flow, self, self.logger)
        except Exception as e:
            self.logger.error(
                f"Error in passive scans for {flow.request.pretty_url}: {e}"
            )
        content_type = flow.response.headers.get("Content-Type", "")
        if (
            200 <= flow.response.status_code < 300
            and "html" in content_type
            and flow.response.text
        ):
            discover_and_queue_targets(
                flow.response.text, flow.request.pretty_url, self
            )
        self.check_response_for_stored_payloads(
            flow.response.text, flow.request.pretty_url
        )

    def register_injection(self, probe_id: str, injection_details: Dict[str, Any]):
        if not probe_id:
            return
        details = injection_details.copy()
        details["timestamp"] = time.time()
        self.injected_payloads[probe_id] = details
        self.logger.debug(
            f"[Injection Tracking] Registered probe {probe_id} (Total: {len(self.injected_payloads)})"
        )

    def check_response_for_stored_payloads(
        self, response_text: Optional[str], current_url: str
    ):
        if not response_text or not self.injected_payloads:
            return
        payload_format_used = self.xss_stored_format
        if "{probe_id}" not in payload_format_used:
            return
        current_time = time.time()
        max_age = self.payload_max_age
        expired_ids = {
            pid
            for pid, details in self.injected_payloads.items()
            if current_time - details.get("timestamp", 0) > max_age
        }
        if expired_ids:
            for pid in expired_ids:
                self.injected_payloads.pop(pid, None)
        payload_ids_to_check = list(self.injected_payloads.keys())
        for probe_id in payload_ids_to_check:
            payload_to_find = payload_format_used.format(probe_id=probe_id)
            if payload_to_find in response_text:
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
                self.injected_payloads.pop(probe_id, None)

    async def _crawl_worker(self):
        self.logger.info("Internal Crawl Worker started.")
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
                        self.check_response_for_stored_payloads(
                            response.text, str(response.url)
                        )
                    except Exception as e:
                        self.logger.warn(
                            f"[CRAWLER TASK] Error visiting {url_to_crawl}: {e}"
                        )
            except asyncio.CancelledError:
                self.logger.info("Crawl worker cancelled.")
                break
            except Exception as e:
                self.logger.error(f"CRITICAL ERROR in Crawl Worker: {e}")
                self.logger.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if url_to_crawl:
                    self.crawl_queue.task_done()

    async def _scan_worker(self):
        self.logger.info("Internal Active Scan Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            scan_details = None
            try:
                scan_details = await self.scan_queue.get()
                target_url_short = scan_details.get("url", "N/A").split("?")[0]
                async with self.semaphore:
                    self.logger.debug(
                        f"[SCAN WORKER] Starting parameter scans for {target_url_short}..."
                    )
                    try:
                        cookies, target_method = (
                            scan_details.get("cookies", {}),
                            scan_details.get("method", "GET").upper(),
                        )
                        if not self.http_client:
                            continue
                        await scan_sqli_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.sqli_payloads,
                            self,
                            self.logger,
                        )
                        await scan_xss_reflected_basic(
                            scan_details,
                            cookies,
                            self.http_client,
                            self.xss_reflected_payloads,
                            self,
                            self.logger,
                        )
                        await scan_xss_stored_inject(
                            scan_details,
                            cookies,
                            self.http_client,
                            self,
                            self.xss_stored_prefix,
                            self.xss_stored_format,
                            self.logger,
                        )
                        await scan_directory_traversal(
                            scan_details, cookies, self.http_client, self, self.logger
                        )
                        if target_method in ["POST", "PUT", "PATCH"]:
                            revisit_url = scan_details["url"]
                            if revisit_url not in self.revisit_in_progress:
                                self.revisit_in_progress.add(revisit_url)
                                self.revisit_queue.put_nowait(revisit_url)
                    except Exception as e:
                        self.logger.error(
                            f"[SCAN TASK] Error during scan of {scan_details.get('url', 'N/A')}: {e}"
                        )
                        self.logger.error(traceback.format_exc())
            except asyncio.CancelledError:
                self.logger.info("Scan worker cancelled.")
                break
            except Exception as e:
                self.logger.error(f"CRITICAL ERROR in Scan Worker: {e}")
                self.logger.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if scan_details:
                    self.scan_queue.task_done()

    async def _revisit_worker(self):
        self.logger.info("Internal Revisit Worker started.")
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
                            continue
                        response = await self.http_client.get(url_to_revisit)
                        self.check_response_for_stored_payloads(
                            response.text, url_to_revisit
                        )
                    except Exception as e:
                        self.logger.warn(
                            f"[Revisit] Error fetching {url_to_revisit}: {e}"
                        )
            except asyncio.CancelledError:
                self.logger.info("Revisit worker cancelled.")
                break
            except Exception as e:
                self.logger.error(f"CRITICAL ERROR in Revisit Worker: {e}")
                self.logger.error(traceback.format_exc())
                await asyncio.sleep(10)
            finally:
                if url_to_revisit:
                    self.revisit_in_progress.discard(url_to_revisit)
                    self.revisit_queue.task_done()

    async def _discovery_worker(self):
        self.logger.info("Internal Content Discovery Worker started.")
        while True:
            if not self.http_client or not self.semaphore:
                await asyncio.sleep(0.5)
                continue
            base_dir_url = None
            try:
                base_dir_url = await self.discovery_queue.get()
                async with self.semaphore:
                    if not self.http_client:
                        continue
                    await scan_content_discovery(
                        base_dir_url,
                        self.discovery_wordlist,
                        {},
                        self.http_client,
                        self,
                        self.logger,
                    )
            except asyncio.CancelledError:
                self.logger.info("Discovery worker cancelled.")
                break
            except Exception as e:
                self.logger.error(
                    f"CRITICAL ERROR in Discovery Worker for {base_dir_url}: {e}"
                )
                self.logger.error(traceback.format_exc())
                if base_dir_url:
                    self.discovery_queue.task_done()

    def websocket_start(self, flow: http.HTTPFlow):
        handle_websocket_start(flow, self)

    def websocket_message(self, flow: http.HTTPFlow):
        handle_websocket_message(flow, self)

    def websocket_error(self, flow: http.HTTPFlow):
        handle_websocket_error(flow, self)

    def websocket_end(self, flow: http.HTTPFlow):
        handle_websocket_end(flow, self)


# --- Addon Registration ---
addons = [MainAddon()]
