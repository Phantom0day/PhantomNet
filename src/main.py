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


def main():
    """
    Main entry point for the application.
    """
    parser = argparse.ArgumentParser(
        description="PhantomSocket - A modular SOCKS5 proxy implementation"
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
        "--port",
        type=int,
        default=const.DEFAULT_SERVER_PORT,
        help=f"Server port (default: {const.DEFAULT_SERVER_PORT})",
    )
    # Add support for authentication config
    server_parser.add_argument(
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
        "--local-host",
        default=const.LOCAL_HOST,
        help=f"Local bind host (default: {const.LOCAL_HOST})",
    )
    client_parser.add_argument(
        "--local-port",
        type=int,
        default=const.DEFAULT_LOCAL_PORT,
        help=f"Local bind port (default: {const.DEFAULT_LOCAL_PORT})",
    )
    client_parser.add_argument(
        "--server-host",
        required=True,
        help="SOCKS5 server host",
    )
    client_parser.add_argument(
        "--server-port",
        type=int,
        default=const.DEFAULT_SERVER_PORT,
        help=f"SOCKS5 server port (default: {const.DEFAULT_SERVER_PORT})",
    )

    # Parse arguments
    args = parser.parse_args()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run in the appropriate mode
    if args.mode == const.MODE_SERVER:
        run_server(args.host, args.port, args.auth, args.auth_file)
    elif args.mode == const.MODE_CLIENT:
        run_client(args.local_host, args.local_port, args.server_host, args.server_port)
    else:
        parser.print_help()


def run_server(host, port, auth="none", auth_file=None):
    """
    Run in server mode.

    Args:
        host: Server host
        port: Server port
        auth: Authentication method
        auth_file: Authentication file path
    """
    global server_proxy

    try:
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


def run_client(local_host, local_port, server_host, server_port):
    """
    Run in client mode.

    Args:
        local_host: Local bind host
        local_port: Local bind port
        server_host: SOCKS5 server host
        server_port: SOCKS5 server port
    """
    global local_proxy

    try:
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
