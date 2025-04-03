# nightcrawler/config.py
# This file can be used for internal constants if needed.
# User-facing configuration is handled via mitmproxy addon options defined in addon.py
# and processed/stored within the MainAddon class instance.

# Example internal constant (if you had one)
# _INTERNAL_DATA_PROCESS_TIMEOUT = 10

# Default payloads moved to addon.py as fallbacks for option processing.
# Configuration values like max concurrency, user-agent etc. are now managed
# via ctx.options in the addon.
