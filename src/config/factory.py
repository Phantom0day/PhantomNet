import logging
from typing import List, Dict, Any, Optional

from src.core import *
from src.config import config
from src.interceptors import *

logger = logging.getLogger(__name__)


class ProfileFactory:
    """Factory for creating interceptor profiles."""

    @staticmethod
    def create_profile(
        profile_name: str, custom_config: Optional[Dict[str, Any]] = None
    ) -> List[BaseInterceptor]:
        """
        Create a list of interceptors for a specific profile.

        Args:
            profile_name: Profile name
            custom_config: Custom configuration overrides

        Returns:
            List[BaseInterceptor]: List of configured interceptors
        """
        if custom_config:
            # Temporarily override configuration
            original_config = config.config.copy()
            config._update_config(custom_config)

        # Get interceptors from configuration
        interceptors = config.create_interceptors(profile_name)

        if custom_config:
            # Restore original configuration
            config.config = original_config

        return interceptors

    @staticmethod
    def create_default_profile() -> List[BaseInterceptor]:
        """Create the default profile with minimal functionality."""
        return [DataForwardingInterceptor()]

    @staticmethod
    def create_stealth_profile(
        encryption_key: str = "default-key-change-me",
    ) -> List[BaseInterceptor]:
        """
        Create a stealth profile with maximum obfuscation.

        Args:
            encryption_key: AES encryption key

        Returns:
            List[BaseInterceptor]: List of configured interceptors
        """
        return [
            # Security layer
            AESEncryptionInterceptor(key=encryption_key),
            # Protocol obfuscation
            ProtocolObfuscationInterceptor(obfuscation_mode="http_header"),
            # Traffic analysis resistance
            DPIEvasionInterceptor(target_entropy=7.2, tcp_split=True),
            EntropyAdjustmentInterceptor(),
            TimingInterceptor(),
            # Packet normalization
            PacketSizeNormalizer(target_sizes=[64, 256, 512, 1024]),
            # Basic functionality
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_http_camouflage_profile() -> List[BaseInterceptor]:
        """Create a profile that disguises traffic as HTTP."""
        return [
            # HTTP camouflage
            HTTPCamouflageInterceptor(),
            # Basic security
            ObfuscationInterceptor(),
            # Traffic analysis resistance
            EntropyAdjustmentInterceptor(),
            # Basic functionality
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_tls_camouflage_profile() -> List[BaseInterceptor]:
        """Create a profile that disguises traffic as TLS."""
        return [
            # TLS camouflage
            TLSCamouflageInterceptor(),
            # Basic security
            ObfuscationInterceptor(),
            # Traffic analysis resistance
            EntropyAdjustmentInterceptor(),
            # Basic functionality
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_video_camouflage_profile() -> List[BaseInterceptor]:
        """Create a profile that disguises traffic as video streaming."""
        return [
            # Video camouflage
            VideoCamouflageInterceptor(),
            # Basic security
            ObfuscationInterceptor(),
            # Traffic analysis resistance
            EntropyAdjustmentInterceptor(),
            # Basic functionality
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_high_speed_profile() -> List[BaseInterceptor]:
        """Create a profile optimized for speed with minimal obfuscation."""
        return [
            # Basic obfuscation only
            ObfuscationInterceptor(),
            # Performance optimization
            ZeroCopyInterceptor(),
            # Basic functionality
            DataForwardingInterceptor(),
        ]
