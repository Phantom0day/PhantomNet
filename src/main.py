import argparse
import logging
import sys
import signal

from src.client import LocalClientProxy
from src.server import RemoteServer
from src.utils import *

# Global variables for clean shutdown
server = None
local_proxy = None
running = True


def setup_logging(level=logging.DEBUG):
    """Setup basic logging"""
    logging.basicConfig(
        level=level, format=DEFAULT_LOGGING_FORMAT, handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)


def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals"""
    global running, server, local_proxy
    print("\nShutting down...")
    running = False
    if server:
        server.stop()
    if local_proxy:
        local_proxy.stop()
    sys.exit(0)


def run_server(args, logger):
    """Run in server mode"""
    global server

    # Create and start the server
    server = RemoteServer(args.host, args.port)
    logger.info(f"Starting remote server on {args.host}:{args.port}")

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        server.stop()


def run_local_proxy(args, logger):
    """Run as local client proxy"""
    global local_proxy

    # Create and start the local proxy
    local_proxy = LocalClientProxy(
        args.local_host, args.local_port, args.server_host, args.server_port
    )

    logger.info(f"Starting local proxy on {args.local_host}:{args.local_port}")
    logger.info(f"Forwarding to remote server at {args.server_host}:{args.server_port}")

    try:
        local_proxy.start()
    except KeyboardInterrupt:
        local_proxy.stop()
    except Exception as e:
        logger.error(f"Local proxy error: {e}")
        local_proxy.stop()


def main():
    """Main entry point"""
    logger = setup_logging()

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="PhantomSocket - A modular SOCKS5 proxy with obfuscation capabilities"
    )

    # Add common options
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Server mode
    server_parser = subparsers.add_parser("server", help="Run as remote server")
    server_parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    server_parser.add_argument(
        "-p", "--port", type=int, default=8388, help="Bind port (default: 8388)"
    )

    # Local proxy mode
    local_parser = subparsers.add_parser("local", help="Run as local client proxy")
    local_parser.add_argument(
        "--local-host",
        default="127.0.0.1",
        help="Local bind address (default: 127.0.0.1)",
    )
    local_parser.add_argument(
        "--local-port", type=int, default=1080, help="Local bind port (default: 1080)"
    )
    local_parser.add_argument(
        "--server-host", required=True, help="Remote server address"
    )
    local_parser.add_argument(
        "--server-port",
        type=int,
        default=8388,
        help="Remote server port (default: 8388)",
    )

    # Parse arguments
    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("src").setLevel(logging.DEBUG)

    # Run in the appropriate mode
    if args.mode == "server":
        run_server(args, logger)
    elif args.mode == "local":
        run_local_proxy(args, logger)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
