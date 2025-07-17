# nightcrawler/websocket_handler.py
# Handles mitmproxy's WebSocket lifecycle hooks, called by the main addon.

from mitmproxy import http, ctx
from typing import TYPE_CHECKING, Any

# Type hint for MainAddon to access its attributes like .websocket_hosts_logged
# Avoids circular import error during static analysis.
if TYPE_CHECKING:
    from nightcrawler.addon import MainAddon


def handle_websocket_start(
    flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any
):
    """
    Called by MainAddon.websocket_start when a WebSocket connection is established.
    Logs a message once per host and suggests the inspection option.
    """
    try:
        # Identify the host for tracking (use flow.request.host for consistency)
        host = flow.request.host
        # Access the tracking set stored within the addon instance
        if host not in addon_instance.websocket_hosts_logged:
            log_message = (
                f"WebSocket connection established to {host}. "
                f"Messages will NOT be logged by default. "
                f"Use '--set nc_inspect_websocket=true' to enable detailed message logging."
            )
            # Use logger directly for operational info messages
            logger.info(f"[WebSocket Detected] {log_message}")
            # Add host to the set stored in the addon instance to prevent re-logging
            addon_instance.websocket_hosts_logged.add(host)
    except Exception as e:
        # Log errors occurring within this hook
        logger.warn(
            f"[WebSocket Handler] Error in handle_websocket_start for {flow.request.host}: {e}"
        )


def handle_websocket_message(
    flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any
):
    """
    Called by MainAddon.websocket_message for each WebSocket message.
    Logs message details only if the nc_inspect_websocket option is enabled.
    """
    try:
        # Check the option directly via ctx.options (available in mitmproxy context)
        if ctx.options.nc_inspect_websocket:
            message = flow.messages[-1]  # The most recent message in the flow
            direction = (
                "-> CtoS" if message.from_client else "<- StoC"
            )  # Client-to-Server or Server-to-Client
            message_type = "Text" if message.is_text else "Binary"
            # Log details at DEBUG level to avoid flooding console by default
            logger.debug(
                f"[WebSocket Message] {direction} {flow.request.host} "
                f"Type: {message_type}, Length: {len(message.content)}"
                # Optional: Add message content preview (use with caution)
                # f", Preview: {message.content[:100]}"
            )
    except Exception as e:
        logger.warn(
            f"[WebSocket Handler] Error processing message for {flow.request.host}: {e}"
        )


def handle_websocket_error(
    flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any
):
    """Called by MainAddon.websocket_error on WebSocket errors."""
    try:
        # Log WebSocket errors as warnings
        logger.warn(
            f"[WebSocket Error] Connection to {flow.request.host}: {flow.error}"
        )
    except Exception as e:
        # Fallback if accessing flow properties fails
        logger.warn(f"[WebSocket Handler] Error in handle_websocket_error hook: {e}")


def handle_websocket_end(flow: http.HTTPFlow, addon_instance: "MainAddon", logger: Any):
    """Called by MainAddon.websocket_end when a WebSocket connection ends."""
    # This hook is usually not needed for logging standard closure.
    # Can add a debug log here if connection termination needs tracking.
    logger.debug(f"[WebSocket Ended] Connection to {flow.request.host} closed.")
    pass


# End of nightcrawler/websocket_scanner.py
