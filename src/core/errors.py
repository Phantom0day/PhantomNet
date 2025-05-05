class ProxyError(Exception):
    """Base exception for proxy errors"""
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(message)

# Then use specific subclasses
class ConnectionError(ProxyError):
    """Connection related errors"""
    pass

class ConfigError(ProxyError):
    """Configuration related errors"""
    pass

