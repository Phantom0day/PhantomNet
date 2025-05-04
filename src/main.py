"""
Main entry point for the PhantomSocket application
"""

import argparse
import signal
import sys
import logging
from typing import Optional

from .server import SOCKS5Server
from .client import LocalClientProxy
from .common import constants as const
from src.auth import NoAuthHandler, UsernamePasswordAuthHandler
from .config import config

logger = logging.getLogger(__name__)

# Global variables for signal handling
server_proxy: Optional[SOCKS5Server] = None
local_proxy: Optional[LocalClientProxy] = None


def signal_handler(sig, frame):
    """
    Handle keyboard interrupt and other termination signals.

    Args:
        sig: Signal number
        frame: Current stack frame
    """
    logger.info("Received interrupt signal, shutting down...")

    if local_proxy and not local_proxy.shutting_down:
        try:
            local_proxy.stop()
        except Exception as e:
            logger.error(f"Error stopping local proxy: {e}")

    if server_proxy and not server_proxy.shutting_down:
        try:
            server_proxy.stop()
        except Exception as e:
            logger.error(f"Error stopping server proxy: {e}")

    sys.exit(0)


def setup_logging():
    """Setup logging based on configuration."""
    log_level = config.get("logging", "level", "INFO")
    log_format = config.get("logging", "format", const.DEFUALT_LOGGING_FORMAT)
    log_file = config.get("logging", "file")

    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # Configure logging
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        filename=log_file,
    )


def generate_default_config(config_path):
    """
    Generate default configuration file.

    Args:
        config_path: Path to save configuration file
    """
    # Set some defaults
    config.config["mode"] = const.MODE_SERVER

    # Save the configuration
    config.save_config(config_path)
    logger.info(f"Default configuration saved to {config_path}")
    print(f"Default configuration saved to {config_path}")


def main():
    """
    Main entry point for the application.
    """
    parser = argparse.ArgumentParser(
        description="PhantomSocket - A modular SOCKS5 proxy implementation"
    )

    # Add config file option
    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="Path to configuration file",
    )

    # Add option to generate default config
    parser.add_argument(
        "--generate-config",
        help="Generate default configuration file and exit",
    )

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Proxy mode")

    # Server mode
    server_parser = subparsers.add_parser(
        const.MODE_SERVER, help="Run as a SOCKS5 server"
    )
    server_parser.add_argument(
        "--host",
        default=const.NONSPEC_HOST,
        help=f"Server host (default: {const.NONSPEC_HOST})",
    )
    server_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=const.DEFAULT_SERVER_PORT,
        help=f"Server port (default: {const.DEFAULT_SERVER_PORT})",
    )
    # Add support for authentication config
    server_parser.add_argument(
        "-a",
        "--auth",
        choices=["none", "userpass"],
        default="none",
        help="Authentication method (default: none)",
    )

    server_parser.add_argument(
        "--auth-file",
        help="Authentication file for username/password (one user:pass per line)",
    )

    # Client mode
    client_parser = subparsers.add_parser(
        const.MODE_CLIENT, help="Run as a local client proxy"
    )
    client_parser.add_argument(
        "-lh",
        "--local-host",
        default=const.LOCAL_HOST,
        help=f"Local bind host (default: {const.LOCAL_HOST})",
    )
    client_parser.add_argument(
        "-lp",
        "--local-port",
        type=int,
        default=const.DEFAULT_LOCAL_PORT,
        help=f"Local bind port (default: {const.DEFAULT_LOCAL_PORT})",
    )
    client_parser.add_argument(
        "-sh",
        "--server-host",
        help="SOCKS5 server host",
    )
    client_parser.add_argument(
        "-sp",
        "--server-port",
        type=int,
        default=const.DEFAULT_SERVER_PORT,
        help=f"SOCKS5 server port (default: {const.DEFAULT_SERVER_PORT})",
    )

    # Parse arguments
    args = parser.parse_args()

    # Generate default config if requested
    if args.generate_config:
        generate_default_config(args.generate_config)
        return

    # Load configuration file if specified
    if args.config:
        config.load_config(args.config)

    # Override config with command line arguments
    if args.mode:
        config.set("mode", None, args.mode)

    # Server mode arguments
    if hasattr(args, "host") and args.host:
        config.set("server", "host", args.host)
    if hasattr(args, "port") and args.port:
        config.set("server", "port", args.port)
    if hasattr(args, "auth") and args.auth:
        config.set("server", "auth", args.auth)
    if hasattr(args, "auth_file") and args.auth_file:
        config.set("server", "auth_file", args.auth_file)

    # Client mode arguments
    if hasattr(args, "local_host") and args.local_host:
        config.set("client", "local_host", args.local_host)
    if hasattr(args, "local_port") and args.local_port:
        config.set("client", "local_port", args.local_port)
    if hasattr(args, "server_host") and args.server_host:
        config.set("client", "server_host", args.server_host)
    if hasattr(args, "server_port") and args.server_port:
        config.set("client", "server_port", args.server_port)

    # Setup logging
    setup_logging()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run in the appropriate mode
    if args.mode == const.MODE_SERVER:
        run_server()
    elif args.mode == const.MODE_CLIENT:
        run_client()
    else:
        parser.print_help()


def run_server():
    """Run in server mode."""
    global server_proxy

    try:
        host = config.get("server", "host", const.NONSPEC_HOST)
        port = config.get("server", "port", const.DEFAULT_SERVER_PORT)
        auth = config.get("server", "auth", "none")
        auth_file = config.get("server", "auth_file")

        auth_handlers = []

        if auth == "none":
            auth_handlers.append(NoAuthHandler())
        elif auth == "userpass":
            credentials = {}

            if auth_file:
                try:
                    with open(auth_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                username, password = line.split(":", 1)
                                credentials[username.strip()] = password.strip()
                except Exception as e:
                    logger.error(f"Error loading auth file: {e}")
                    sys.exit(1)

            auth_handlers.append(UsernamePasswordAuthHandler(credentials))

        server_proxy = SOCKS5Server(host, port, auth_handlers)
        server_proxy.start()
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


def run_client():
    """Run in client mode."""
    global local_proxy

    try:
        local_host = config.get("client", "local_host", const.LOCAL_HOST)
        local_port = config.get("client", "local_port", const.DEFAULT_LOCAL_PORT)
        server_host = config.get("client", "server_host")
        server_port = config.get("client", "server_port", const.DEFAULT_SERVER_PORT)

        if not server_host:
            logger.error("SOCKS5 server host must be specified")
            sys.exit(1)

        local_proxy = LocalClientProxy(
            local_host,
            local_port,
            server_host,
            server_port,
        )
        local_proxy.start()
    except Exception as e:
        logger.error(f"Client error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
