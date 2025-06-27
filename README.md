# nightcrawler-mitm

![alt text](https://github.com/thesp0nge/nightcrawler-mitm/blob/main/logo_transparent.png?raw=true)

Version: 0.9.0

A mitmproxy addon for background passive analysis, crawling, and basic active
scanning, designed as a security researcher's sidekick.

**WARNING: BETA Stage - Use with caution, especially active scanning features**

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

```sh
pip install nightcrawler-mitm`
```

It's recommended to install it in a virtual environment. For development/local
testing:

- Navigate to project root directory (containing pyproject.toml)
- Activate your virtual environment (e.g., source .venv/bin/activate)

```sh
pip install -e .
```

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

## CONFIGURATION

Nightcrawler configuration follows this precedence:

1. Command-line --set options (highest precedence)
2. Values in configuration file
3. Built-in defaults (lowest precedence)

**Configuration File:**

- By default, Nightcrawler looks for a YAML configuration file at:
  - `~/.config/nightcrawler-mitm/config.yaml` (on Linux/macOS, standard)
  - `%APPDATA%/nightcrawler-mitm/config.yaml` (on Windows, needs check)
  - _Fallback:_ `~/.nightcrawler-mitm/config.yaml` (if XDG path not
    found/writable)
- You can specify a different configuration file path using the `--nc-config`
  option when running Nightcrawler (passed via `--set`):
  `nightcrawler --set nc_config=/path/to/my_config.yaml ...`
- The configuration file uses YAML format. Keys should match the addon option
  names (without the `--set`).

_Example `config.yaml`:_

```yaml
# ~/.config/nightcrawler-mitm/config.yaml
# Nightcrawler Configuration Example

# Target scope (REQUIRED if not using --set nc_scope)
nc_scope: example.com,internal.dev

# Worker concurrency
nc_max_concurrency: 10

# Custom User-Agent
nc_user_agent: "My Custom Scanner Bot/1.0"

# Custom payload files (paths relative to config file or absolute)
# nc_sqli_payload_file: payloads/custom_sqli.txt
# nc_xss_reflected_payload_file: /opt/payloads/xss.txt

# Stored XSS settings
nc_xss_stored_prefix: MyProbe
nc_xss_stored_format: "<nc_probe data='{probe_id}'/>"
nc_payload_max_age: 7200 # Track payloads for 2 hours

# Output files (relative paths resolved against default data dir, absolute paths used as is)
# nc_output_file: nightcrawler_results.jsonl # Saved in default data dir
# nc_output_html: /var/www/reports/scan_report.html # Saved to absolute path

# WebSocket inspection
nc_inspect_websocket: false
```

### Command-Line Overrides (--set)

You can always override defaults or config file values using --set. This takes
the highest precedence.

```
nightcrawler --set nc_scope=specific-target.com --set nc_max_concurrency=3
```

To see all available nc*options and their current effective values (after
considering defaults, config file, and --set), run: nightcrawler --options |
grep nc*

### Default Data Directory & Output Paths

- If you specify relative paths for nc_output_file or nc_output_html (either in
  the config file or via --set), Nightcrawler will attempt to save them relative
  to a default data directory:
  - Linux/macOS (XDG): ~/.local/share/nightcrawler-mitm/
  - Windows (approx): %LOCALAPPDATA%/nightcrawler-mitm/
- If you specify absolute paths (e.g., /tmp/report.html), they will be used
  directly.
- Nightcrawler will attempt to create these directories if they don't exist.

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

```

```
