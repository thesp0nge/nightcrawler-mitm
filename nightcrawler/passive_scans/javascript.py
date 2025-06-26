# nightcrawler/passive_scans/javascript.py
# Passive checks to identify JavaScript libraries and their versions.

import re
from mitmproxy import http
from typing import Dict, Optional, List, TYPE_CHECKING, Pattern, Tuple, Any  # Added Any
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Library Fingerprints (with improved regex) ---
JS_LIBRARY_PATTERNS: List[Tuple[str, Pattern]] = [
    (
        "jQuery",
        re.compile(r"jquery(?:-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min|\.slim)?\.js"),
    ),
    ("jQuery UI", re.compile(r"jquery-ui-([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js")),
    ("React", re.compile(r"react(?:-dom)?(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("AngularJS", re.compile(r"angular(?:-|\.js\?v=)([0-9]+\.[0-9]+\.[0-9]+)")),
    ("Vue.js", re.compile(r"vue(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("Bootstrap", re.compile(r"bootstrap(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    (
        "Lodash",
        re.compile(r"lodash(?:-|\.)([0-9]+\.[0-9]+\.[0-9]+)(?:-)?(?:\.min)?\.js"),
    ),
    ("Moment.js", re.compile(r"moment\.([0-9]+\.[0-9]+\.[0-9]+)\.min\.js")),
    ("D3.js", re.compile(r"d3\.v([0-9]+\.[0-9]+\.[0-9]+)")),
]


def check_javascript_libraries(
    response: http.Response,
    url: str,
    addon_instance: "MainAddon",
    logger: Any,  # Accept a logger object
):
    """
    Parses HTML content to find <script src="..."> tags and identify
    known JavaScript libraries and their versions from the URL.
    """
    content_type = response.headers.get("Content-Type", "").lower()
    if "html" not in content_type:
        return

    response_text = response.text
    if not response_text:
        return

    logger.debug(f"[JS Lib Scan] Analyzing script tags in {url}")
    found_libraries = set()

    try:
        soup = BeautifulSoup(response_text, "html.parser")
        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get("src")
            if not src:
                continue

            for lib_name, pattern in JS_LIBRARY_PATTERNS:
                match = pattern.search(src)
                if match:
                    version = next((g for g in match.groups() if g is not None), None)
                    if version:
                        lib_key = f"{lib_name}@{version}"
                        if lib_key not in found_libraries:
                            addon_instance._log_finding(
                                level="INFO",
                                finding_type="Passive Scan - JS Library Found",
                                url=url,
                                detail=f"Identified Library: {lib_name} version {version}",
                                evidence={
                                    "script_url": src,
                                    "library": lib_name,
                                    "version": version,
                                },
                            )
                            found_libraries.add(lib_key)
                        break
    except Exception as e:
        logger.warn(f"[JS Lib Scan] Error parsing HTML for {url}: {e}")
