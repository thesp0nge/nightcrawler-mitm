# nightcrawler-mitm

A mitmproxy addon for background passive analysis, crawling, and basic active
scanning, designed as a security researcher's sidekick.

**WARNING: Beta Stage - Use with caution, especially active scanning features**

## FEATURES

- Acts as an HTTP/HTTPS proxy.
- Performs passive analysis (security headers, cookie attributes, basic info
  disclosure).
- Crawls the target application to discover new endpoints based on visited
  pages.
- Runs basic active scans for low-hanging fruit (Reflected XSS, basic SQLi -
  Error/Time-based) in the background.
- All output and logs are directed to the console.
- Target scope is configurable via command-line argument.

## INSTALLATION

You can install `nightcrawler` directly from PyPI using pip:

pip install nightcrawler-mitm

It's recommended to install it in a virtual environment.

## USAGE

Once installed, a new command `nightcrawler` becomes available. This command
wraps `mitmdump`, automatically loading the nightcrawler addon. You MUST specify
the target scope using the `--nc-scope` option.

You can pass any other valid `mitmproxy` arguments (like `--ssl-insecure`, `-p`,
`-v`) to the `nightcrawler` command.

1. Configure your Browser/Client: Set your browser (or system) to use 127.0.0.1
   on port 8080 (or the port you specify using -p) as its HTTP and HTTPS proxy.

2. Install Mitmproxy CA Certificate: For HTTPS interception, ensure the
   mitmproxy CA certificate is installed and trusted in your browser/system.
   While the proxy is running, visit <http://mitm.it> and follow the
   instructions.

3. Run Nightcrawler:

   - Specify Target Scope (REQUIRED!): nightcrawler --nc-scope example.com

   - Multiple domains (comma-separated, no spaces): nightcrawler --nc-scope
     example.com,sub.example.com,another.net

   - Common Options (Combine as needed): nightcrawler -p 8081 --nc-scope
     example.com nightcrawler --ssl-insecure --nc-scope internal-site.local
     nightcrawler -v --nc-scope example.com # Use -v or -vv for debug logs
     nightcrawler --nc-max-concurrency 10 --nc-scope secure.com nightcrawler
     --nc-sqli-payload-file sqli.txt --nc-scope test.org

   - Show Nightcrawler & Mitmproxy version: nightcrawler --version

   - Show all Nightcrawler and Mitmproxy options: nightcrawler --help

   NOTE: If --nc-scope is not provided, Nightcrawler will run but will not
   process any requests.

4. Browse: Start Browse the target application(s) specified in the scope. Output
   from passive analysis, crawling, and active scans will appear in the terminal
   where `nightcrawler` is running. Look for [Passive Scan], [CRAWLER
   DISCOVERY],
   [SQLi FOUND?], [XSS FOUND?], [STORED XSS? FOUND] messages.

## CONFIGURATION

Nightcrawler uses mitmproxy's option system. Pass arguments when running the
`nightcrawler` command:

- `--nc-scope DOMAIN[,DOMAIN,...]` (Required): Target domain(s)
  (comma-separated).
- `--nc-max-concurrency INT` (Default: 5): Max concurrent background tasks.
- `--nc-user-agent STRING` (Default: Nightcrawler-MITM/x.y.z): User-Agent for
  worker requests.
- `--nc-payload-max-age INT` (Default: 3600): Max age (seconds) for tracking
  Stored XSS probes.
- `--nc-sqli-payload-file FILEPATH` (Default: Uses built-in list): File with
  SQLi payloads (one per line).
- `--nc-xss-reflected-payload-file FILEPATH` (Default: Uses built-in list): File
  with Reflected XSS payloads (one per line).
- `--nc-xss-stored-prefix STRING` (Default: "ncXSS"): Prefix for unique Stored
  XSS probe IDs.
- `--nc-xss-stored-format STRING` (Default: ""): Format string for Stored XSS
  probe payload (must contain `{probe_id}`).

You can also use standard mitmproxy options like `-p PORT`,
`--listen-host HOST`, `--ssl-insecure`, `-v`, `-vv`, etc.

## LIMITATIONS

- Basic Active Scans: The SQLi and XSS scanners are very basic and intended only
  for obvious low-hanging fruit. They CANNOT detect complex vulnerabilities
  (e.g., Stored XSS, blind SQLi beyond time-based, DOM XSS, template injection,
  etc.). DO NOT rely solely on this tool for comprehensive vulnerability
  assessment.

- Stored XSS: The current XSS scanner only checks for immediate reflection and
  CANNOT detect Stored XSS.

- Resource Usage: Background crawling and scanning can consume significant
  network bandwidth, CPU, and memory resources. Adjust MAX_CONCURRENT_SCANS in
  `config.py` if needed.

- False Positives/Negatives: Expect potential false positives (especially from
  passive checks or simple XSS reflection) and many false negatives
  (vulnerabilities missed by the basic scanners).

## LICENSE

This project is licensed under the [MIT License]. See the LICENSE file for details.

## CONTRIBUTING (Optional)

Contributions are welcome! Please open an issue or submit a pull request on the
GitHub repository: [https://github.com/thesp0nge/nightcrawler-mitm]
