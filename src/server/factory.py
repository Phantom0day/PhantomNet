from src.server import RemoteServer as SecureSOCKS5Server
from src.interceptors import *


class ProxyServerFactory:
    @staticmethod
    def create_server(
        profile: str, host: str, port: int, config=None
    ) -> SecureSOCKS5Server:
        """Create a server with a pecific profile of interceptors"""

        if profile == "stealth":
            interceptors = [
                AESEncryptionInterceptor(config.get("encryption_key")),
                ProtocolObfuscationInterceptor("http_header"),
                DPIEvasionInterceptor(target_entropy=7.2),
                EntropyAdjustmentInterceptor(),
            ]
        elif profile == "high_speed":
            interceptors = [
                ObfuscationInterceptor(),  # Minimal obfuscation
                ZeroCopyInterceptor(),  # Performance optimization
            ]
        elif profile == "balanced":
            interceptors = [
                AESEncryptionInterceptor(config.get("encryption_key")),
                HTTPCamouflageInterceptor,
                ConnectionPoolInterceptor(),
            ]
        else:
            interceptors = config.get("interceptors", [])

        return SecureSOCKS5Server(host, port, interceptors, config)
