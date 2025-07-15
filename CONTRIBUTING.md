# Contributing to Nightcrawler

First off, thank you for considering contributing! Nightcrawler is an
open-source project, and we welcome any contributions, from bug reports to new
features.

This guide provides instructions for developers who want to add their own custom
scanners.

## How to Add a New Active Scanner

Nightcrawler is designed with a modular architecture to make adding new active
scanners as easy as possible. All active scanners that test request parameters
live in the `nightcrawler/active_scans/` directory.

### Step 1: Create Your Scanner File

1.  **Find the Skeleton:** The easiest way to start is to use our template. You
    can find it in the project's root directory at:
    `examples/skeleton_scanner.py`.
2.  **Copy the Skeleton:** Copy this file into the `nightcrawler/active_scans/`
    directory.
3.  **Rename It:** Give it a descriptive name for the vulnerability you want to
    test (e.g., `ssrf_scanner.py`, `command_injection.py`).

### Step 2: Implement Your Scanner Logic

Open your new scanner file inside `nightcrawler/active_scans/`. It contains a
single function, `scan_...`, which you will modify.

1.  **Define Payloads:** At the top of the file, define a list or set of
    payloads your scanner will use.
2.  **Implement Logic:** Inside the `scan_...` function, the basic structure is
    already there:
    - It receives a `target_info` dictionary with all the details of an
      intercepted request.
    - It loops through all parameters found in the request.
    - It loops through all your defined payloads.
    - It injects each payload into each parameter.
    - It sends a new HTTP request with the modified data.
3.  **Analyze the Response:** This is the most important part. Inside the
    `try...except` block, after the `response = await http_client.request(...)`
    line, you must add your custom logic to check if the `response` indicates a
    vulnerability. This could be checking `response.status_code`, looking for
    specific strings or patterns in `response.text`, or checking for time
    delays.
4.  **Log Findings:** If you find a vulnerability, use the centralized logger to
    report it:
    ```python
    addon_instance._log_finding(
        level="ERROR", # Can be "ERROR", "WARN", or "INFO"
        finding_type="My New Vulnerability Type",
        url=url,
        detail="A clear description of what was found.",
        evidence={"param": param_name, "payload": payload} # A dictionary of useful evidence
    )
    ```

### Step 3: Integrate Your Scanner into the Addon

1.  **Open `nightcrawler/addon.py`.**
2.  **Import Your Function:** At the top of the file, add a new line to import
    your scanner function:
    ```python
    from nightcrawler.active_scans.my_scanner import scan_my_vulnerability
    ```
3.  **Call Your Function:** Find the `_scan_worker` method. Inside its `try`
    block, add a call to your new scanner, making sure to `await` it and pass
    all the required arguments:
    ```python
    # Inside _scan_worker in addon.py
    # ... after the other scanner calls ...
    await scan_my_vulnerability(
        scan_details,
        cookies,
        self.http_client,
        # self.my_payloads, # If you made it configurable
        self, # The addon_instance
        self.logger # The logger
    )
    ```

### Step 4: (Optional) Add a Configuration Option

If you want to make parts of your scanner configurable (like enabling/disabling
it or providing a custom payload file), you can add a new option in
`nightcrawler/addon.py` by following the existing pattern in the `load()` and
`configure()` methods.

### Step 5: Write Tests!

We use `pytest` for testing.

1.  Create a new test file in the `tests/` directory (e.g.,
    `tests/test_my_scanner.py`).
2.  Use `tests/test_active_discovery.py` as a template.
3.  Write tests that use `respx` to mock server responses and verify that your
    scanner correctly calls `_log_finding` when it detects a vulnerability and
    doesn't call it when it shouldn't.

Thank you for contributing!
