# nightcrawler/active_scans/__init__.py
import importlib
import inspect
import os
import pkgutil
from typing import List, Type
from nightcrawler.active_scans.base import ActiveScanner

def discover_scanners() -> List[Type[ActiveScanner]]:
    """
    Dynamically discovers and returns all ActiveScanner subclasses 
    defined in the modules within this package.
    """
    scanners = []
    # Get the directory of the current package
    package_dir = os.path.dirname(__file__)
    
    # Iterate through all modules in the current package
    for loader, module_name, is_pkg in pkgutil.iter_modules([package_dir]):
        # Skip base and __init__
        if module_name in ("base", "__init__"):
            continue
            
        # Import the module dynamically
        full_module_name = f"nightcrawler.active_scans.{module_name}"
        try:
            module = importlib.import_module(full_module_name)
            
            # Find all classes in the module that inherit from ActiveScanner
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ActiveScanner) and obj is not ActiveScanner:
                    scanners.append(obj)
        except Exception as e:
            # We don't have a logger here easily, so we just print or ignore
            print(f"Error loading module {full_module_name}: {e}")
            
    return scanners
