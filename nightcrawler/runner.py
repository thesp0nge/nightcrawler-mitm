# nightcrawler/runner.py (Final Version using Absolute Path Workaround)
import sys
import os
import pathlib
import traceback  # For printing full tracebacks on unexpected errors

try:
    # --- Calculate necessary paths ---
    runner_script_path = pathlib.Path(__file__).resolve()
    # Assuming runner.py is directly inside the 'nightcrawler' package directory
    package_dir = runner_script_path.parent
    project_root = package_dir.parent  # Directory containing the 'nightcrawler' dir
    # Construct the absolute path to the main addon file
    addon_file_path = package_dir / "addon.py"

    # --- Basic Sanity Check ---
    # Verify that the calculated addon file actually exists
    if not addon_file_path.is_file():
        print(
            f"CRITICAL ERROR: Addon script not found at expected path: {addon_file_path}",
            file=sys.stderr,
        )
        print(
            f"(Based on runner script location: {runner_script_path})", file=sys.stderr
        )
        sys.exit(1)

    # --- Add project root to sys.path (might still be needed for imports *within* the addon) ---
    # Although mitmproxy loads the file directly, the addon script itself might
    # perform imports relative to the package structure later.
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        # print(f"--- DEBUG: Prepending project root to sys.path: {project_root_str} ---", file=sys.stderr) # Optional debug
        sys.path.insert(0, project_root_str)

    # --- Import Dependencies AFTER path setup (if needed) ---
    # Imports specifically needed for the runner logic itself
    from mitmproxy.tools.main import mitmdump

    # Import version info from the package
    from nightcrawler import __version__ as nightcrawler_version

except ImportError as e:
    print(
        f"CRITICAL ERROR: Failed to import dependencies (mitmproxy or nightcrawler package).",
        file=sys.stderr,
    )
    print(
        f"Ensure required packages are installed in the virtual environment ('{sys.prefix}').",
        file=sys.stderr,
    )
    print(f"Import error details: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    # Catch other potential errors during initialization
    print(f"CRITICAL ERROR during runner initialization: {e}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)


def main():
    """
    Entry point for the 'nightcrawler' command line tool.
    Handles '--version' and then starts mitmdump, loading the addon
    using its absolute file path as a workaround for module resolution issues.
    """
    # --- Handle --version Flag ---
    if "--version" in sys.argv:
        print(f"Nightcrawler version: {nightcrawler_version}")
        try:
            # Try to get mitmproxy version directly
            from mitmproxy import version as mitmproxy_version_module

            print(f"Mitmproxy version: {mitmproxy_version_module.VERSION}")
        except ImportError:
            print("Mitmproxy version: (could not determine)")
        sys.exit(0)  # Exit after printing version

    # --- Prepare and Run mitmdump ---
    # Use the calculated absolute file path as the argument for '-s'
    addon_arg = str(addon_file_path)

    # Basic arguments for mitmdump: load our addon script via its file path
    mitm_args = ["-s", addon_arg]

    # Append all other arguments passed by the user to the 'nightcrawler' command
    # This includes '--set', '-p', '-v', '--ssl-insecure', etc.
    mitm_args.extend(sys.argv[1:])

    print(
        f"--- Starting Nightcrawler v{nightcrawler_version} (using addon file: {addon_arg}) ---",
        file=sys.stderr,
    )
    try:
        # Execute mitmdump with the addon file path and user arguments
        mitmdump(mitm_args)
    except SystemExit:
        # Let mitmproxy handle its own exit via SystemExit
        raise
    except Exception as e:
        # Catch unexpected errors during mitmproxy execution
        print(f"\n--- ERROR running mitmdump ---", file=sys.stderr)
        print(f"{e}", file=sys.stderr)
        print(
            f"--- Args passed to mitmdump: {' '.join(mitm_args)} ---", file=sys.stderr
        )
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Entry point when script is run directly
    main()
