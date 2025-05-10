class ProxyError(Exception):
    """Base exception for proxy errors"""

    def __init__(self, message: str = "", code=0):
        self.message = message
        self.code = code
        super().__init__(message)


class SocksError(ProxyError): ...


class SocksVersionError(SocksError): ...


class SocksAuthError(SocksError): ...


class ConnectionError(ProxyError): ...


class ConfigError(ProxyError): ...
