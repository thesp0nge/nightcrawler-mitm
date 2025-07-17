# nightcrawler/runner.py
import sys
import os
import pathlib
import traceback

# --- Path Adjustment for Editable Installs ---
try:
    project_root = pathlib.Path(__file__).parent.resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
except Exception:
    pass

# --- Import Dependencies ---
try:
    from mitmproxy.tools.main import mitmdump
    from nightcrawler import __version__ as nightcrawler_version
except ImportError as e:
    print(f"CRITICAL ERROR: Failed to import dependencies.", file=sys.stderr)
    sys.exit(1)


def main():
    """
    Entry point for the 'nightcrawler' command.
    Starts the interactive mitmproxy tool, running in quiet mode by default.
    A custom -d/--debug flag enables Nightcrawler's debug logging.
    """
    if "--version" in sys.argv:
        print(f"Nightcrawler version: {nightcrawler_version}")
        try:
            from mitmproxy import version as mitmproxy_version_module

            print(f"Mitmproxy version: {mitmproxy_version_module.VERSION}")
        except ImportError:
            print("Mitmproxy version: (could not determine)")
        sys.exit(0)

    # --- Verbosity and Debug Logic ---
    user_args = sys.argv[1:]
    final_args = []
    nightcrawler_debug = False

    # 1. Parse for our custom debug flag first and remove it
    custom_debug_flags = {"-d", "--debug"}
    for arg in user_args:
        if arg in custom_debug_flags:
            nightcrawler_debug = True
        else:
            final_args.append(arg)

    # 2. Check for mitmproxy's built-in verbosity/quiet flags
    mitm_verbosity_flags = {"-q", "--quiet", "-v", "-vv", "-vvv", "--verbose"}
    is_mitm_verbosity_set = any(arg in final_args for arg in mitm_verbosity_flags)

    # 3. Apply quiet mode to mitmproxy by default if no verbosity flag was passed
    if not is_mitm_verbosity_set:
        final_args.insert(0, "-q")
        print(
            "--- Running in Quiet Mode (default). Use -v for mitmproxy logs or -d for Nightcrawler debug logs. ---",
            file=sys.stderr,
        )

    # 4. Pass our debug preference to the addon using --set
    if nightcrawler_debug:
        # Use a format that is safe for the command line
        final_args.extend(["--set", "nc_debug_mode=true"])

    # --- Prepare and Run mitmproxy ---
    # We load the addon via its absolute path for reliability in editable installs
    addon_file_path = pathlib.Path(__file__).parent.resolve() / "addon.py"
    if not addon_file_path.is_file():
        print(
            f"CRITICAL ERROR: Addon script not found at path: {addon_file_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    addon_arg = str(addon_file_path)
    mitm_args = ["-s", addon_arg]
    mitm_args.extend(final_args)

    print(
        f"--- Starting Nightcrawler v{nightcrawler_version} (Interactive Mode) ---",
        file=sys.stderr,
    )
    try:
        mitmdump(mitm_args)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n--- ERROR running mitmproxy ---", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
