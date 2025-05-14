import argparse
import logging
import os
import sys
import signal

# Ensure we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.proxy import *
from src.config import ConfigLoader
from src.utils import *

# Global variables for clean shutdown
server = None
client = None
running = True


def setup_logging(config):
    """Setup logging"""
    level_str = config.get("general", "log_level", "DEBUG")
    log_file = config.get("general", "log_file")
    verbose = config.get("general", "verbose", False)

    # Convert string log level to logging constant
    level = getattr(logging, level_str.upper(), logging.INFO)

    # If verbose, override log level to DEBUG
    if verbose:
        level = logging.DEBUG

    # Configure logging
    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=level,
        format=DEFAULT_LOGGING_FORMAT,
        handlers=handlers,
        force=True,
    )


def signal_handler(sig, frame):
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(lambda: asyncio.create_task(shutdown()))


async def shutdown():
    """Handle termination signals"""
    global running, server, client
    print("\nShutting down...")
    running = False
    if server:
        await server.stop()
    if client:
        await client.stop()
    # sys.exit(0)


async def run_server(config: ConfigLoader):
    """Run in server mode"""
    global server

    # Get configuration
    host = config.get("server", "host", "0.0.0.0")
    port = config.get("server", "port", 8388)
    interceptors = await create_interceptors(config)

    # Create and start server
    server = ServerProxy(config, host, port, interceptors)
    log.info(f"Starting remote server on {host}:{port}")
    log.info(f"Using profile: {config.get_active_profile()}")
    log.info(
        f"Active interceptors: {', '.join([i.__class__.__name__ for i in interceptors])}"
    )

    try:
        await server.start()
    except KeyboardInterrupt:
        await server.stop()
    except Exception as e:
        log.error(f"Server error")
        log.exception(e)
        await server.stop()


async def run_client(config):
    """Run as local client proxy"""
    global client

    # Get configuration
    local_host = config.get("client", "host", "127.0.0.1")
    local_port = config.get("client", "port", 1080)
    server_host = config.get("client", "server_host")
    server_port = config.get("client", "server_port", 8388)

    if not server_host:
        log.error("Server host not specified. Use --server-host or set it in config.")
        return

    interceptors = await create_interceptors(config)

    # Create and start the local proxy
    client = ClientProxy(
        config,
        local_host,
        local_port,
        server_host,
        server_port,
        interceptors,
    )

    log.info(f"Starting local proxy on {local_host}:{local_port}")
    log.info(f"Remote server: {server_host}:{server_port}")
    log.info(f"Profile: {config.get_active_profile()}")
    log.info(f"Interceptors: {', '.join([i.__class__.__name__ for i in interceptors])}")

    try:
        await client.start()
    except KeyboardInterrupt:
        await client.stop()
    except Exception as e:
        log.error(f"Local proxy error")
        log.exception(e)
        await client.stop()


async def create_interceptors(config: ConfigLoader):
    return config.create_interceptors()


def generate_config(path):
    """Generate default configuration file"""
    config = ConfigLoader()
    if config.save_config(path):
        print(f"Config saved to {path}")
    else:
        print(f"Failed to save config to {path}")


def main():
    """Main entry point"""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="PhantomSocket - A modular SOCKS5 proxy with obfuscation capabilities"
    )

    # Common options
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

    # Mode subparsers
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Server mode
    server_parser = subparsers.add_parser("server", help="Run as remote server")
    server_parser.add_argument("--host", help="Bind address (default: 0.0.0.0)")
    server_parser.add_argument(
        "-p", "--port", type=int, help="Bind port (default: 8388)"
    )

    # Local proxy mode
    local_parser = subparsers.add_parser("client", help="Run as local client proxy")
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

    args = parser.parse_args()

    # Handle generate-config
    if args.generate_config:
        generate_config(args.generate_config)
        return

    # Load configuration
    config_file = args.config

    # Try default locations if not specified
    if not config_file:
        default_locations = [
            "./config.yaml",
            "./config.yml",
            "./config.json",
            os.path.expanduser("~/.phantomsocket/config.yaml"),
            "/etc/phantomsocket/config.yaml",
        ]

        for loc in default_locations:
            if os.path.exists(loc):
                config_file = loc
                break

    # Load config and update from args
    config = ConfigLoader(config_file)
    config.update_from_args(args)

    # Setup logging
    setup_logging(config)

    async def _task():
        global loop
        loop = asyncio.get_running_loop()

        # Register signal handler
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Run in the appropriate mode
        if args.mode == "server":
            await run_server(config)
        elif args.mode == "client":
            await run_client(config)
        else:
            parser.print_help()

    asyncio.run(_task())
