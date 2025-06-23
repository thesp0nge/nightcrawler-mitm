# nightcrawler/passive_scans/javascript.py
# Passive checks to identify JavaScript libraries and their versions.

import re
from mitmproxy import http
from typing import Dict, Optional, List, TYPE_CHECKING, Pattern, Tuple, Any
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Library Fingerprints (with improved regex) ---
# A list of tuples: (Library Name, Regex Pattern to capture version)
# Regexes are designed to find version numbers in common file naming schemes.
# They capture the version string in a group.
JS_LIBRARY_PATTERNS: List[Tuple[str, Pattern]] = [
    # Pattern now handles jquery-3.6.0.js, jquery.3.6.0.min.js, etc.
    (
        "jQuery",
        re.compile(r"jquery(?:-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min|\.slim)?\.js"),
    ),
    ("jQuery UI", re.compile(r"jquery-ui-([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js")),
    # Pattern now handles react@17.0.2, react-dom.17.0.2, etc.
    ("React", re.compile(r"react(?:-dom)?(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    # Pattern now handles angular.js?v=1.8.2, angular-1.8.2.js, etc.
    ("AngularJS", re.compile(r"angular(?:-|\.js\?v=)([0-9]+\.[0-9]+\.[0-9]+)")),
    ("Vue.js", re.compile(r"vue(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    # Pattern now handles bootstrap@4.5.2, bootstrap-4.5.2, bootstrap.4.5.2
    ("Bootstrap", re.compile(r"bootstrap(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    (
        "Lodash",
        re.compile(r"lodash(?:-|\.)([0-9]+\.[0-9]+\.[0-9]+)(?:-)?(?:\.min)?\.js"),
    ),
    (
        "Moment.js",
        re.compile(r"moment(?:-with-locales)?\.js\?v=([0-9]+\.[0-9]+\.[0-9]+)"),
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
    found_libraries = set()  # To avoid duplicate logging on the same page

    try:
        soup = BeautifulSoup(response_text, "html.parser")
        # Find all script tags with a 'src' attribute
        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get("src")  # Use .get() for safety
            if not src:
                continue

            # Check the script src against all known library patterns
            for lib_name, pattern in JS_LIBRARY_PATTERNS:
                # Use search() to find a match anywhere in the src string
                match = pattern.search(src)
                if match:
                    # The version is in the first (or only) capture group
                    # Use a loop to find the first non-None group, as some regexes have optional groups
                    version = next((g for g in match.groups() if g is not None), None)

                    if version:
                        lib_key = f"{lib_name}@{version}"
                        if lib_key not in found_libraries:
                            addon_instance._log_finding(
                                level="INFO",
                                finding_type="Passive Scan - JS Library Found",
                                url=url,  # The page where the script was found
                                detail=f"Identified Library: {lib_name} version {version}",
                                evidence={
                                    "script_url": src,
                                    "library": lib_name,
                                    "version": version,
                                },
                            )
                            found_libraries.add(lib_key)
                        # Once a match is found for a given src, stop checking other patterns
                        break
    except Exception as e:
        # Use the passed logger object
        logger.warn(
            f"[JS Lib Scan] Error parsing HTML or analyzing scripts for {url}: {e}"
        )


# End of nightcrawler/passive_scans/javascript.py
