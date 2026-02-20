# nightcrawler/passive_scans/base.py
from mitmproxy import http
from typing import Dict, Any, List, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class PassiveScanner:
    """Base class for all passive scanners."""
    
    name: str = "BasePassiveScanner"
    
    def __init__(self, addon_instance: "MainAddon", logger: Any):
        self.addon_instance = addon_instance
        self.logger = logger

    async def scan_request(self, request: http.Request):
        """Optional: Implement if the scanner needs to check requests."""
        pass

    async def scan_response(self, response: http.Response, url: str):
        """Optional: Implement if the scanner needs to check responses."""
        pass
