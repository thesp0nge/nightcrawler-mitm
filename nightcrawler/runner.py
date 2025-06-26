# nightcrawler/runner.py
import sys
import os
import pathlib
import traceback

try:
    # This block ensures that when the 'nightcrawler' script is run,
    # the project's root directory is on Python's path. This allows
    # absolute imports like 'from nightcrawler.config import ...' to work.
    project_root = pathlib.Path(__file__).parent.resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Now that the path is set, we can import
    from mitmproxy.tools.main import mitmdump
    from nightcrawler import __version__ as nightcrawler_version
except ImportError as e:
    print(
        f"CRITICAL ERROR: Failed to import dependencies. Is Nightcrawler installed correctly in editable mode?",
        file=sys.stderr,
    )
    print(f"Import error details: {e}", file=sys.stderr)
    sys.exit(1)


def main():
    """Entry point for the 'nightcrawler' command line tool."""
    if "--version" in sys.argv:
        print(f"Nightcrawler version: {nightcrawler_version}")
        try:
            from mitmproxy import version as mitmproxy_version_module

            print(f"Mitmproxy version: {mitmproxy_version_module.VERSION}")
        except ImportError:
            print("Mitmproxy version: (could not determine)")
        sys.exit(0)

    # Use the absolute file path to the addon script as our reliable loading method
    addon_file_path = project_root / "nightcrawler" / "addon.py"
    if not addon_file_path.is_file():
        print(
            f"CRITICAL ERROR: Addon script not found at path: {addon_file_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    addon_arg = str(addon_file_path)
    mitm_args = ["-s", addon_arg]
    mitm_args.extend(sys.argv[1:])

    print(
        f"--- Starting Nightcrawler v{nightcrawler_version} (using addon file: {addon_arg}) ---",
        file=sys.stderr,
    )
    try:
        mitmdump(mitm_args)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n--- ERROR running mitmdump ---", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
