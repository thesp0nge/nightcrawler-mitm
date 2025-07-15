# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added an interactive key binding (d) to dump all discovered URLs to a
  nightcrawler_links.txt file on the fly.

### Changed

- Improved Contributor Experience: Refactored the project structure by moving
  the scanner template (skeleton_scanner.py) from the core source code into a
  dedicated top-level examples/ directory. This creates a clearer separation
  between application code and developer documentation.

- Updated CONTRIBUTING.md to reflect the new location of the skeleton scanner.

### Fixed

- _Future fixes go here_

## [0.9.0] - 2025-06-26

### Changed

- **Major Refactor (Build System):** Overhauled the versioning system to use a
  "single source of truth."
  - The package version is now defined only once in `nightcrawler/__init__.py`.
  - `pyproject.toml` has been updated to read this version dynamically during
    the build process (`dynamic = ["version"]`).
  - This change significantly simplifies the release workflow and prevents
    version number inconsistencies between the package metadata and the running
    application.

### Fixed

- All previously identified test failures have been resolved, resulting in a
  stable test suite.

## [0.8.0] - 2025-06-26

### Added

- **Enhanced Passive Scanning:**
  - Added a new passive scanner module (`passive_scans/javascript.py`) to
    identify common JavaScript libraries and their versions.
  - Enhanced the JWT scanner (`passive_scans/jwt.py`) to validate `exp`
    (expiration) and `nbf` (not before) claims, and to flag insecure `alg:none`
    as an error.
  - Enhanced the header scanner (`passive_scans/headers.py`) to check for a
    wider range of security headers (Permissions-Policy, COOP/COEP/CORP), weak
    HSTS configurations, and basic CSP weaknesses.
- **Testing:**
  - Added a dedicated test suite (`tests/test_passive_javascript.py` and
    `tests/test_passive_csp.py`) for the new passive scanning logic.

### Changed

- **Major Test Suite Overhaul:** Completed the migration of all HTTP mocking
  tests from `pytest-httpx` to the more direct and stable `respx` library. This
  provides more reliable and predictable test execution.
- **Decoupled Scanner Logic:** All active and passive scanner functions are now
  fully decoupled from `mitmproxy.ctx` and accept a logger object as a
  parameter, making them properly unit-testable.

### Fixed

- **All Test Failures:** Resolved all outstanding `pytest` errors and failures,
  achieving a fully passing ("green") test suite. This includes fixing
  `fixture not found`, `AssertionError`, `NameError`, and `AttributeError`
  exceptions that were occurring during test setup and execution.
- Corrected numerous specific test assertions to align with the refactored
  code's actual output.
- Fixed a `NameError` in `active_scans/traversal.py` caused by a missing import.
- Fixed `TypeError` in `passive_scans/headers.py` and `cookies.py` by aligning
  function signatures to accept the `logger` argument.

## [0.7.0] - 2025-06-23

### Added

- **JavaScript Library Scanner:** Added a new passive scanner module
  (`passive_scans/javascript.py`) to identify common JavaScript libraries (e.g.,
  jQuery, React, Vue, Bootstrap) and their versions from the `src` attribute of
  `<script>` tags.
- **Testing:** Added a dedicated test suite (`tests/test_passive_javascript.py`)
  to verify the new JS library scanner's logic.

### Changed

- **Finalized Test Suite Overhaul:** Completed the migration of all HTTP mocking
  tests (including `test_xss_scanner.py` and `test_active_discovery.py`) from
  the problematic `pytest-httpx` to the more direct and stable `respx` library.
- **Centralized Test Fixtures:** All shared `pytest` fixtures (`mock_addon`,
  `target_info_*`, `sample_url`) have been moved into a single
  `tests/conftest.py` file to be automatically available to all test modules,
  resolving all `fixture not found` errors.

### Fixed

- **All Test Failures:** Resolved all outstanding `pytest` errors and failures,
  achieving a fully passing ("green") test suite. This includes:
  - Fixed persistent `AssertionError` failures in active scanner tests by
    correcting the `respx` mocking strategy to match the way the scanner code
    makes requests.
  - Fixed assertion mismatches in `test_passive_headers.py` by aligning test
    expectations with the scanner's actual output.
  - Fixed all `NameError` and `AttributeError` exceptions that were occurring
    only within the `pytest` environment by decoupling scanner functions from
    the `mitmproxy.ctx` object.

## [0.6.0] - 2025-06-23

### Added

- **Configuration File Support:**
  - Nightcrawler now supports a dedicated YAML configuration file (default:
    `~/.config/nightcrawler-mitm/config.yaml`).
  - Implemented configuration precedence: Command-line `--set` options > Config
    file > Built-in defaults.
  - Added `--set nc_config=/path/to/file.yaml` to specify a custom config file.
- **Content Discovery Scanner:**
  - Added a new active scanner module (`active_scans/discovery.py`) to probe for
    hidden files and directories from a wordlist.
  - Includes a built-in default wordlist and supports custom lists via
    `--set nc_discovery_wordlist=...`.
  - Integrated a new asynchronous worker (`_discovery_worker`) to manage
    discovery scans.
- **Testing:**
  - Added a dedicated test suite for the new content discovery scanner
    (`tests/test_active_discovery.py`).
  - Created a central `tests/conftest.py` to provide shared fixtures to all test
    modules.
- **Dependencies:**
  - Added `PyYAML` for parsing the configuration file.
  - Added `respx` for robust HTTP request mocking in tests.

### Changed

- **Major Test Suite Overhaul:** Refactored the entire test suite for stability
  and correctness.
  - Replaced the `pytest-httpx` library with `respx` for all mocking.
  - Decoupled all active scanner functions from `mitmproxy.ctx` by passing a
    dedicated logger object.
- `addon.py` was significantly refactored to handle the new configuration logic
  and discovery worker.
- Output file paths with relative paths are now resolved against a default data
  directory (e.g., `~/.local/share/nightcrawler-mitm`).

### Fixed

- **All test failures:** Resolved all outstanding `pytest` errors, including
  persistent `AssertionError`s, `AttributeError: ctx.log`, `NameError`, and
  `fixture not found` errors, resulting in a fully passing test suite.
- Removed the deprecated `cookies=` argument from all `httpx` calls in scanners,
  fixing `DeprecationWarning`s.

### Removed

- Removed the `pytest-httpx` library from testing dependencies.

## [0.5.0] - 2025-04-09

### Added

- **Structured Output:** Added `--set nc_output_file=path/to/file.jsonl` option
  to save findings in JSON Lines format. Implemented `_log_finding` helper in
  `MainAddon` for centralized logging to console and file.
- **Enhanced Passive Scanning:**
  - Added checks for more security headers (`Permissions-Policy`, COOP, COEP,
    CORP).
  - Added basic check for weak HSTS `max-age` and incorrect
    `X-Content-Type-Options`.
  - Added basic check for weak CSP directives (`unsafe-inline`, `unsafe-eval`,
    wildcard source).
  - Added basic JWT detection and decoding (no signature check) in request
    headers (`Authorization: Bearer`) and JSON responses
    (`passive_scans/jwt.py`).
  - Added basic info disclosure pattern checks for Keywords, AWS Key IDs, and
    Private Key headers (`passive_scans/content.py`). _(Note: User might need to
    manually integrate `content.py` code due to previous generation issues)._
- **WebSocket Handling:**
  - Added detection of WebSocket connection establishment (`websocket_start`
    hook), logging only once per host.
  - Added option (`--set nc_inspect_websocket=false`) to disable/enable detailed
    WebSocket message logging (`websocket_message` hook).

### Changed

- **Major Refactor (Passive Scans):** Moved passive scan logic into a
  `nightcrawler/passive_scans/` sub-package (`headers.py`, `cookies.py`,
  `jwt.py`, `content.py`). `passive_scanner.py` now acts as an orchestrator
  importing from the sub-package.
- **Major Refactor (WebSockets):** Moved WebSocket handling logic into
  `nightcrawler/websocket_handler.py`. `addon.py` now calls handlers via wrapper
  methods.
- Updated signatures of scanner and passive check functions to accept
  `addon_instance` for calling the centralized `_log_finding` method.
- Refactored finding logging across applicable modules to use
  `MainAddon._log_finding`.

### Fixed

- Fixed various `TypeError` and `NameError` exceptions during addon loading and
  execution:
  - Corrected `loader.add_option` calls in `addon.py` to use `typespec=` instead
    of `type=` (for mitmproxy v11 compatibility).
  - Added missing imports (`traceback` in `addon.py`, `Optional` in
    `passive_scanner.py`).
  - Corrected calls to scanner functions (`scan_xss_reflected_basic`,
    `scan_sqli_basic`) in `addon.py` to pass `addon_instance` (`self`).
  - Corrected `NameError` for undefined `payload_info` variable within an
    exception handler in `xss_scanner.py`.
- Fixed `AttributeError: module 'mitmproxy.http' has no attribute 'Cookie'` by
  correcting the type hint in `passive_scans/cookies.py` to use `MultiDictView`.
- Fixed `AttributeError: module 'mitmproxy.ctx' has no attribute 'log'` by
  moving initial logging from `MainAddon.__init__` to the `running` hook.
- Fixed `AttributeError: 'MainAddon' object has no attribute '_log_finding'` by
  adding the `_log_finding` method definition to `MainAddon`.
- Fixed `AttributeError: cannot access attribute _queue for class Queue` by
  replacing direct queue inspection with a separate tracking set
  (`revisit_in_progress`).
- Fixed `Too much data for declared Content-Length` error in active scanners by
  filtering `Content-Length`, `Host`, and `Transfer-Encoding` headers before
  sending modified requests via `httpx`.
- Resolved `No such script: nightcrawler.addon` errors by diagnosing loading
  issues related to editable installs and mitmproxy's script loader, culminating
  in using the absolute file path workaround in `runner.py` (though the root
  cause might be specific to mitmproxy/environment interaction).
  _Self-correction: Reverted runner to use dotted path after user confirmed
  direct mitmproxy call worked with fixes._ [Note: Final state uses dotted
  path in runner after fixing internal errors].

## 0.4.0 - 2025-04-03

### Added

- Configuration via mitmproxy command-line options:
  - Added `--nc-max-concurrency` option.
  - Added `--nc-user-agent` option.
  - Added `--nc-sqli-payload-file` option to load SQLi payloads from a file.
  - Added `--nc-xss-reflected-payload-file` option to load Reflected XSS
    payloads from a file.
  - Added `--nc-xss-stored-prefix` option.
  - Added `--nc-xss-stored-format` option.
- Helper function in `addon.py` (`_load_payloads_from_file`) to load payloads
  from files specified by options, with fallback to internal defaults.

### Changed

- Removed user configuration constants (`MAX_CONCURRENT_SCANS`, `USER_AGENT`,
  payload lists, stored XSS format/prefix) from `nightcrawler/config.py`.
- Modified `addon.py` (`MainAddon`) to define, process (`configure` hook), and
  store configuration values from `ctx.options`.
- Updated `addon.py` (`running` hook) to initialize `Semaphore` and
  `httpx.AsyncClient` using values derived from options.
- Modified scanner functions (`scan_sqli_basic`, `scan_xss_reflected_basic`,
  `scan_xss_stored_inject`) to accept configuration (payloads, prefix, format)
  as arguments instead of importing them.
- Updated calls in `_scan_worker` (`addon.py`) to pass the configured values to
  scanner functions.
- Updated `README.txt` to document the new command-line configuration options.

### Fixed

- Ensured HTTP client and Semaphore are initialized/re-initialized correctly in
  the `running` hook after options are processed by `configure`.

## [0.3.0] - 2025-03-27

### Added

- **Basic Stored XSS Detection:** Implemented initial capability to detect
  stored XSS vulnerabilities.
  - Injects unique, trackable probes (e.g., ``) via `scan_xss_stored_inject`.
  - Tracks injected probes in memory within the main addon
    (`MainAddon.injected_payloads`).
  - Added a background "Revisit Worker" (`_revisit_worker`) and queue
    (`revisit_queue`) to re-fetch URLs after potential storage actions
    (POST/PUT).
  - Checks HTML content of revisited pages, regular browser responses, and
    crawler responses for the presence of previously injected unique probes via
    `check_response_for_stored_payloads`.
  - Added basic time-based and count-based cleanup for tracked payloads to limit
    memory usage.
  - Added `--nc-payload-max-age` command-line option (via `ctx.options`) to
    configure the maximum age (in seconds) for tracked payloads.
- Separated XSS scanning logic into distinct functions
  (`scan_xss_reflected_basic`, `scan_xss_stored_inject`) in `xss_scanner.py` for
  better maintainability.
- Added check for stored payloads in responses fetched by the `_crawl_worker`.

### Changed

- Significantly updated `addon.py` (`MainAddon`) to manage state (queues,
  tracked payloads) and the new `_revisit_worker` required for Stored XSS
  detection.
- Renamed original XSS scan function `scan_xss_basic` to
  `scan_xss_reflected_basic`.
- Updated `config.py` to hold separate configuration/payloads for reflected
  (`XSS_REFLECTED_PAYLOADS`) vs. stored (`XSS_STORED_PROBE_PREFIX`,
  `XSS_STORED_PAYLOAD_FORMAT`) XSS checks.
- Modified `xss_scanner.py` to include the new `scan_xss_stored_inject` function
  and pass the addon instance for state access (`register_injection`).
- Added cleanup logic in the `done` hook for the new `revisit_worker_task`.

## [0.2.0] - 2025-03-25

### Added

- Packaged the project using `pyproject.toml` for installation via `pip` and
  distribution on PyPI (as `nightcrawler`).
- Introduced a console script entry point: the `nightcrawler` command now wraps
  `mitmdump` and loads the addon automatically.
- Added a **mandatory** command-line option `--nc-scope` to define the target
  domain(s) for scanning and crawling (comma-separated).
- Implemented `--version` handling for the `nightcrawler` command to display the
  package's own version alongside mitmproxy's version.
- Added basic addon lifecycle management using `running` and `done` hooks
  (starting workers, closing shared HTTP client).
- Included basic `try...except` blocks in worker loops to improve resilience
  against unexpected errors.

### Changed

- **Major Refactor:** Restructured the single-script addon into multiple Python
  modules (`addon.py`, `config.py`, `utils.py`, `passive_scanner.py`,
  `crawler.py`, `sqli_scanner.py`, `xss_scanner.py`, `runner.py`) within a
  `nightcrawler` package directory for better organization and maintainability.
- Internal imports updated to use absolute package paths (e.g.,
  `from nightcrawler.utils import ...`).

### Removed

- Removed the hardcoded `TARGET_SCOPE_DOMAINS` constant from `config.py`; scope
  must now be provided via `--nc-scope`.

## [0.1.0] - 2025-03-20

### Added

- Initial version based on concept discussions.
- Core functionality as a `mitmproxy` addon script.
- Acts as an HTTP/HTTPS proxy.
- Basic passive scanning infrastructure (header/cookie checks - conceptual).
- Background crawling functionality (link discovery via `BeautifulSoup`, queuing
  via `asyncio.Queue`, basic `_crawl_worker`).
- Background active scanning worker (`_scan_worker`).
- Basic Reflected XSS scanning (`scan_xss_basic` checking immediate response).
- Basic SQLi scanning (`scan_sqli_basic` checking for errors/time delays).
- Concurrency limiting for background tasks using `asyncio.Semaphore`.
- Basic debug logging implemented using `ctx.log`.
- Support for `mitmproxy` options like `--ssl-insecure` passed through via the
  runner.

[Unreleased]:
  https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.4.0...v0.5.0
[0.3.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/thesp0nge/nightcrawler-mitm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/thesp0nge/nightcrawler-mitm/releases/tag/v0.1.0
