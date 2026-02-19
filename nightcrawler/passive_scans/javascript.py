# nightcrawler/passive_scans/javascript.py
# Passive checks to identify JavaScript libraries and their versions.

import re
from mitmproxy import http
from typing import Dict, Optional, List, TYPE_CHECKING, Pattern, Tuple, Any  # Added Any
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon

# --- Library Fingerprints & OSV Mapping ---
JS_LIBRARY_PATTERNS: List[Tuple[str, Pattern]] = [
    ("jQuery", re.compile(r"jquery(?:-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min|\.slim)?\.js")),
    ("jQuery UI", re.compile(r"jquery-ui-([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js")),
    ("React", re.compile(r"react(?:-dom)?(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("AngularJS", re.compile(r"angular(?:-|\.js\?v=)([0-9]+\.[0-9]+\.[0-9]+)")),
    ("Vue.js", re.compile(r"vue(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("Bootstrap", re.compile(r"bootstrap(?:@|-|\.)([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("Lodash", re.compile(r"lodash(?:-|\.)([0-9]+\.[0-9]+\.[0-9]+)(?:-)?(?:\.min)?\.js")),
]

# Map common names to the package name used in the OSV ecosystem (often npm)
JS_LIB_OSV_MAP: Dict[str, str] = {
    "jQuery": "jquery",
    "jQuery UI": "jquery-ui",
    "React": "react",
    "AngularJS": "angular",
    "Vue.js": "vue",
    "Bootstrap": "bootstrap",
    "Lodash": "lodash",
}


async def _check_osv_for_vulnerabilities(
    lib_details: Dict[str, str], http_client: "httpx.AsyncClient", addon_instance: "MainAddon", logger: Any
):
    """Queries the OSV API for vulnerabilities for a given library."""
    lib_name = lib_details.get("library")
    version = lib_details.get("version")
    url = lib_details.get("url")

    if not lib_name or not version:
        return

    package_name = JS_LIB_OSV_MAP.get(lib_name)
    if not package_name:
        logger.debug(f"[OSV Check] No OSV package name mapping for '{lib_name}'. Skipping.")
        return

    osv_url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": "npm"},
    }

    try:
        response = await http_client.post(osv_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulns"):
                for vuln in data["vulns"]:
                    vuln_id = vuln.get("id", "N/A")
                    summary = vuln.get("summary", "No summary available.")
                    addon_instance._log_finding(
                        level="WARN",
                        finding_type="Vulnerable JS Library Found",
                        url=url,
                        detail=f"Vulnerable '{lib_name} @ {version}' found. OSV ID: {vuln_id}. Summary: {summary}",
                        evidence={
                            "library": lib_name,
                            "version": version,
                            "vulnerability_id": vuln_id,
                            "script_url": lib_details.get("script_url"),
                        },
                        confidence="HIGH",
                    )
    except Exception as e:
        logger.error(f"[OSV Check] Error querying OSV API for {package_name}@{version}: {e}")


def check_javascript_libraries(
    response: http.Response,
    url: str,
    addon_instance: "MainAddon",
    logger: Any,
):
    """
    Parses HTML to find JS libraries and queues them for vulnerability checks.
    """
    content_type = response.headers.get("Content-Type", "").lower()
    if "html" not in content_type or not response.text:
        return

    logger.debug(f"[JS Lib Scan] Analyzing script tags in {url}")
    found_libraries = set()

    try:
        soup = BeautifulSoup(response.text, "html.parser")
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
                            # Log initial finding
                            addon_instance._log_finding(
                                level="INFO",
                                finding_type="Passive Scan - JS Library Found",
                                url=url,
                                detail=f"Identified Library: {lib_name} version {version}",
                                evidence={"script_url": src, "library": lib_name, "version": version},
                                confidence="LOW",
                            )
                            found_libraries.add(lib_key)

                            # Queue for vulnerability check
                            lib_details = {
                                "library": lib_name,
                                "version": version,
                                "url": url,
                                "script_url": src,
                            }
                            addon_instance.vuln_check_queue.put_nowait(lib_details)
                        break
    except Exception as e:
        logger.warn(f"[JS Lib Scan] Error parsing HTML for {url}: {e}")
