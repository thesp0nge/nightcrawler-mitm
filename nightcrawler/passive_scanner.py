# nightcrawler/passive_scanner.py
import importlib
import inspect
import os
import pkgutil
from mitmproxy import http
from typing import TYPE_CHECKING, Any, List, Type
from nightcrawler.passive_scans.base import PassiveScanner

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

def discover_passive_scanners() -> List[Type[PassiveScanner]]:
    """Dynamically discovers all PassiveScanner subclasses."""
    scanners = []
    package_dir = os.path.join(os.path.dirname(__file__), 'passive_scans')
    for loader, module_name, is_pkg in pkgutil.iter_modules([package_dir]):
        if module_name in ("base", "__init__"): continue
        full_module_name = f"nightcrawler.passive_scans.{module_name}"
        try:
            module = importlib.import_module(full_module_name)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, PassiveScanner) and obj is not PassiveScanner:
                    scanners.append(obj)
        except Exception as e:
            print(f"Error loading passive module {full_module_name}: {e}")
    return scanners

async def run_all_passive_checks(flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any):
    """Executes all available passive checks."""
    addon_instance.stats["passive_total"] += 1
    url = flow.request.pretty_url

    for scanner in addon_instance.passive_scanners:
        try:
            if flow.request:
                await scanner.scan_request(flow.request)
            if flow.response:
                await scanner.scan_response(flow.response, url)
        except Exception as e:
            logger.error(f"Error in passive scanner '{scanner.name}' for {url}: {e}")
