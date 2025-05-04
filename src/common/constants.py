"""
Constants used throught the SOCKS5 proxy implementation.
"""

# SOCKS5 protocol constants
SOCKS_VERSION = 5

# SOCKS5 proxy mode
MODE_SERVER = "server"
MODE_CLIENT = "client"

# SOCKS5 command types
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# SOCKS5 address types
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4


# SOCKS5 reply codes
REPLY_SUCCESS = 0
REPLY_GENERAL_FAILURE = 1
REPLY_CONNECTION_NOT_ALLOWED = 2
REPLY_NETWORK_UNREACHABLE = 3
REPLY_HOST_UNREACHABLE = 4
REPLY_CONNECTION_REFUSED = 5
REPLY_TTL_EXPIRED = 6
REPLY_COMMAND_NOT_SUPPORTED = 7
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 8

# SOCKS5 authentication methods
AUTH_NO_AUTH = 0
AUTH_GSSAPI = 1
AUTH_USERNAME_PASSWORD = 2
AUTH_NO_ACCEPTABLE_METHODS = 255

# Default logging format
DEFUALT_LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Default timeout values (in seconds)
DEFAULT_SOCKET_TIMEOUT = 10
DEFAULT_SELECT_TIMEOUT = 1
DEFAULT_THREAD_JOIN_TIMEOUT = 0.5

# Default buffer size for socket operations
DEFAULT_BUFFER_SIZE = 4096

# Default ports
DEFAULT_SERVER_PORT = 8080
DEFAULT_LOCAL_PORT = 1080
LOCAL_HOST = "127.0.0.1"
NONSPEC_HOST = "0.0.0.0"

# Application version constants
APP_VERSION_MAJOR = 0
APP_VERSION_MINOR = 1
APP_VERSION_PATCH = 1
APP_VERSION = f"{APP_VERSION_MAJOR}.{APP_VERSION_MINOR}.{APP_VERSION_PATCH}"

# Version compatibility codes
VERSION_COMPATIBLE = 0
VERSION_INCOMPATIBLE = 1

# UDP related constants
UDP_FRAG_NO = 0  # No fragmentation
UDP_DEFAULT_BUFFER_SIZE = 65507  # Max UDP packet size

# Authentication methods details
AUTH_USERNAME_PASSWORD_VERSION = 1
AUTH_USERNAME_PASSWORD_SUCCESS = 0
AUTH_USERNAME_PASSWORD_FAILURE = 1

# Max lengths
MAX_USERNAME_LENGTH = 255
MAX_PASSWORD_LENGTH = 255

# Config key & default values
KEY_MODE = "mode"
KEY_SERVER = MODE_SERVER
KEY_PORT = "port"
KEY_HOST = "host"
KEY_AUTH = "auth"
KEY_AUTH_FILE = "auth_file"

KEY_CLIENT = MODE_CLIENT
KEY_LOCAL_HOST = "local_host"
KEY_LOCAL_PORT = "local_port"
KEY_SERVER_HOST = "server_host"
KEY_SERVER_PORT = "server_port"

KEY_LOG = "logging"


KEY_POOL = "connection_pool"

KEY_MAX_SIZE = "max_size"
KEY_DNS_CACHE_TTL = "dns_cache_ttl"
KEY_DNS_SERVERS = "dns_servers"
KEY_DISABLE_DNS_CACHE = "disable_dns_cache"
KEY_DNS_TIMEOUT = "dns_timeout"
KEY_DNS_RETRIES = "dns_retries"

DEFAULT_DNS_SERVERS = [
    "8.8.8.8",  # Google DNS
    "1.1.1.1",  # Cloudflare DNS
    "9.9.9.9",  # Quad9 DNS
    "208.67.222.222",  # Open DNS
]
