import argparse
import logging
import os
import sys
import signal

from src.client import LocalClientProxy
from src.server import RemoteServer
from src.config import ConfigLoader
from src.utils import *

# Global variables for clean shutdown
server = None
local_proxy = None
running = True


def setup_logging(config):
    """Setup logging based on configuration"""
    log_level_str = config.get("general", "log_level", "INFO")
    log_file = config.get("general", "log_file")
    verbose = config.get("general", "verbose", False)

    # Convert string log level to logging constant
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    # If verbose, override log level to DEBUG
    if verbose:
        log_level = logging.DEBUG

    # Configure logging
    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=log_level, format=DEFAULT_LOGGING_FORMAT, handlers=handlers
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


def run_server(config, logger):
    """Run in server mode"""
    global server

    # Get server configuration
    host = config.get("server", "host", "0.0.0.0")
    port = config.get("server", "port", 8388)

    # Create interceptors from active profile
    interceptors = config.create_interceptors()

    # Create and start the server
    server = RemoteServer(host, port, interceptors)
    logger.info(f"Starting remote server on {host}:{port}")
    logger.info(f"Using profile: {config.get_active_profile()}")
    logger.info(
        f"Active interceptors: {', '.join([i.__class__.__name__ for i in interceptors])}"
    )

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        server.stop()


def run_local_proxy(config, logger):
    """Run as local client proxy"""
    global local_proxy

    # Get local proxy configuration
    local_host = config.get("local", "host", "127.0.0.1")
    local_port = config.get("local", "port", 1080)
    server_host = config.get("local", "server_host")
    server_port = config.get("local", "server_port", 8388)

    if not server_host:
        logger.error(
            "Server host not specified. Use --server-host or set it in config."
        )
        return

    # Create interceptors from active profile
    interceptors = config.create_interceptors()

    # Create and start the local proxy
    local_proxy = LocalClientProxy(
        local_host, local_port, server_host, server_port, interceptors
    )

    logger.info(f"Starting local proxy on {local_host}:{local_port}")
    logger.info(f"Forwarding to remote server at {server_host}:{server_port}")
    logger.info(f"Using profile: {config.get_active_profile()}")
    logger.info(
        f"Active interceptors: {', '.join([i.__class__.__name__ for i in interceptors])}"
    )

    try:
        local_proxy.start()
    except KeyboardInterrupt:
        local_proxy.stop()
    except Exception as e:
        logger.error(f"Local proxy error: {e}")
        local_proxy.stop()


def generate_default_config(output_path):
    """Generate default configuration file"""
    config = ConfigLoader()
    if config.save_config(output_path):
        print(f"Default configuration saved to {output_path}")
    else:
        print(f"Failed to save default configuration to {output_path}")


def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="PhantomSocket - A modular SOCKS5 proxy with obfuscation capabilities"
    )

    # Add common options
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("--profile", help="Use specific profile from configuration")
    parser.add_argument(
        "--generate-config",
        metavar="FILE",
        help="Generate default configuration file and exit",
    )

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Server mode
    server_parser = subparsers.add_parser("server", help="Run as remote server")
    server_parser.add_argument("--host", help="Bind address (default: 0.0.0.0)")
    server_parser.add_argument(
        "-p", "--port", type=int, help="Bind port (default: 8388)"
    )

    # Local proxy mode
    local_parser = subparsers.add_parser("local", help="Run as local client proxy")
    local_parser.add_argument(
        "--local-host",
        help="Local bind address (default: 127.0.0.1)",
    )
    local_parser.add_argument(
        "--local-port", type=int, help="Local bind port (default: 1080)"
    )
    local_parser.add_argument("--server-host", help="Remote server address")
    local_parser.add_argument(
        "--server-port",
        type=int,
        help="Remote server port (default: 8388)",
    )

    # Parse arguments
    args = parser.parse_args()

    # Handle generate-config option
    if args.generate_config:
        generate_default_config(args.generate_config)
        return

    # Load configuration
    # First try the command-line specified config file
    config_file = args.config

    # If not specified, try default locations
    if not config_file:
        default_locations = [
            "./config.yaml",
            "./config.yml",
            "./config.json",
            os.path.expanduser("~/.phantomsocket/config.yaml"),
            "/etc/phantomsocket/config.yaml",
        ]

        for location in default_locations:
            if os.path.exists(location):
                config_file = location
                break

    # Load the configuration
    config = ConfigLoader(config_file)

    # Update configuration from command-line arguments
    config.update_from_args(args)

    # Setup logging based on configuration
    logger = setup_logging(config)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run in the appropriate mode
    if args.mode == "server":
        run_server(config, logger)
    elif args.mode == "local":
        run_local_proxy(config, logger)
    else:
        parser.print_help()
