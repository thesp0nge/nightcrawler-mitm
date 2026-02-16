# nightcrawler/config.py
# This file contains the default configuration constants for Nightcrawler.

from typing import List, Set

# Import version to be used in the default User-Agent string
try:
    from nightcrawler import __version__ as nightcrawler_version
except ImportError:
    nightcrawler_version = "unknown"

# --- Default Payloads and Scanner Settings ---
DEFAULT_SQLI_PAYLOADS: List[str] = ["'", '"', "''", "' OR '1'='1", "' OR SLEEP(5)--"]
DEFAULT_XSS_REFLECTED_PAYLOADS: List[str] = [
    "<script>alert('XSSR')</script>",
    "\"><script>alert('XSSR')</script>",
    "'\"/><svg/onload=alert('XSSR')>",
]
DEFAULT_XSS_STORED_PREFIX: str = "ncXSS"
DEFAULT_XSS_STORED_FORMAT: str = "<!-- {probe_id} -->"
# DEFAULT_XSS_STORED_FORMAT: str = "[[probe_id:{probe_id}]]" # Safe format
DEFAULT_PAYLOAD_MAX_AGE: int = 3600  # 1 hour in seconds

# --- ADDED: Payloads for new scanners ---
DEFAULT_CMD_INJECTION_PAYLOADS: List[str] = [
    "| sleep 5 #",
    "&& sleep 5",
    "; sleep 5",
    "| whoami",
    "&& id",
]
DEFAULT_SSTI_PAYLOADS: List[str] = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]

# --- Default Worker and Client Settings ---
DEFAULT_MAX_CONCURRENCY: int = 5
DEFAULT_USER_AGENT: str = f"Nightcrawler-MITM/{nightcrawler_version}"

# --- Default Content Discovery Settings ---
DEFAULT_DISCOVERY_WORDLIST: Set[str] = {
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".env",
    "config.json",
    "docker-compose.yml",
    "package.json",
    "web.config",
    "README.md",
    "backup",
    "temp",
    "tmp",
    "admin",
    "dashboard",
    "logs",
    "test.php",
    "info.php",
    "index.php.bak",
    "index.html.old",
}

# End of nightcrawler/config.py
