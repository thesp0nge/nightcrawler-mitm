# nightcrawler-mitm

Version: 0.5.0

A mitmproxy addon for background passive analysis, crawling, and basic active
scanning, designed as a security researcher's sidekick.

**WARNING: Alpha Stage - Use with caution, especially active scanning features
**

## FEATURES

- Acts as an HTTP/HTTPS proxy.
- Performs passive analysis:
  - Security Headers (HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy,
    COOP, COEP, CORP, basic weakness checks).
  - Cookie Attributes (Secure, HttpOnly, SameSite).
  - JWT Detection & Decoding (in Headers and JSON responses).
  - Basic Info Disclosure checks (Comments, basic keyword context - Note:
    API/Key/Secret checks temporarily disabled).
- Crawls the target application to discover new endpoints.
- Runs basic active scans for low-hanging fruit:
  - Reflected XSS (basic reflection check).
  - SQL Injection (basic error/time-based checks).
  - Stored XSS (basic probe injection and revisit check).
- Configurable target scope, concurrency, payloads, and output via command-line
  options.
- Logs findings to console and optionally to a JSONL file.

## INSTALLATION

You can install `nightcrawler-mitm` directly from PyPI using pip (once
published):

# pip install nightcrawler-mitm

It's recommended to install it in a virtual environment. For development/local
testing:

# Navigate to project root directory (containing pyproject.toml)

# Activate your virtual environment (e.g., source .venv/bin/activate)

pip install -e .

## USAGE

Once installed, a new command `nightcrawler` becomes available. This command
wraps `mitmdump`, automatically loading the addon. You MUST specify the target
scope using the `--set nc_scope=...` option.

You can pass any other valid `mitmproxy` arguments (like `--ssl-insecure`, `-p`,
`-v`) AND Nightcrawler-specific options using the `--set name=value` syntax.

1. Configure Browser/Client: Set proxy to 127.0.0.1:8080 (or specified port).
2. Install Mitmproxy CA Certificate: Visit <http://mitm.it> via proxy.
3. Run Nightcrawler:

   - Specify Target Scope (REQUIRED!): nightcrawler --set nc_scope=example.com

   - Common Options (Combine as needed): nightcrawler -p 8081 --set
     nc_scope=example.com nightcrawler --ssl-insecure --set
     nc_scope=internal-site.local nightcrawler -v --set nc_scope=example.com #
     Use -v or -vv for debug logs nightcrawler --set nc_max_concurrency=10 --set
     nc_scope=secure.com nightcrawler --set nc_sqli_payload_file=sqli.txt --set
     nc_output_file=findings.jsonl --set nc_scope=test.org

   - Show Nightcrawler & Mitmproxy version: nightcrawler --version

   - Show all Nightcrawler and Mitmproxy options (look for 'nc\_' prefix):
     nightcrawler --options

   NOTE: If nc_scope is not set, Nightcrawler will run but remain idle.

4. Browse: Browse the target application(s). Findings appear in the terminal and
   optionally in the specified JSONL file.

## CONFIGURATION VIA COMMAND LINE (--set)

Use mitmproxy's `--set name=value` syntax:

- `--set nc_scope=DOMAIN[,DOMAIN,...]` (Required): Target domain(s).
- `--set nc_max_concurrency=INT` (Default: 5): Max concurrent background tasks.
- `--set nc_user_agent=STRING` (Default: Nightcrawler-MITM/x.y.z): User-Agent
  for worker requests.
- `--set nc_payload_max_age=INT` (Default: 3600): Max age (seconds) for tracking
  Stored XSS probes.
- `--set nc_sqli_payload_file=FILEPATH` (Default: Uses built-in list): File with
  SQLi payloads.
- `--set nc_xss_reflected_payload_file=FILEPATH` (Default: Uses built-in list):
  File with Reflected XSS payloads.
- `--set nc_xss_stored_prefix=STRING` (Default: "ncXSS"): Prefix for unique
  Stored XSS probe IDs.
- `--set nc_xss_stored_format=STRING` (Default: ""): Format for Stored XSS
  probe.
- `--set nc_output_file=FILEPATH` (Default: "" - Disabled): Path to save
  findings in JSONL format.

## LIMITATIONS

- Basic Active Scans: Scanners are basic, intended for low-hanging fruit. Cannot
  detect complex vulnerabilities. DO NOT rely solely on this tool.
- Stored XSS Detection: Basic implementation, may miss cases and have FPs.
- Info Disclosure: Content checks for keys/secrets are basic and currently
  disabled pending refactoring.
- Resource Usage: Tune `--set nc_max_concurrency`.
- False Positives/Negatives: Expected. Manual verification is required.

## LICENSE

This project is licensed under the MIT License. See the LICENSE file for
details.

## CONTRIBUTING (Optional)

Contributions welcome! See the GitHub repository:
<https://github.com/thesp0nge/nightcrawler-mitm>
