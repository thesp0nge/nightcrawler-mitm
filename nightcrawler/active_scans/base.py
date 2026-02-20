# nightcrawler/active_scans/base.py
import httpx
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

class ActiveScanner:
    """Base class for all active scanners."""
    
    name: str = "BaseScanner"
    
    def __init__(self, addon_instance: "MainAddon", logger: Any):
        self.addon_instance = addon_instance
        self.logger = logger

    async def run(
        self,
        target_info: Dict[str, Any],
        cookies: Dict[str, str],
        http_client: httpx.AsyncClient,
    ):
        """Main entry point for the scanner. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement run()")
