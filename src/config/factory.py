import logging
from typing import List, Dict, Any, Optional

from src.core import *
from src.config import config
from src.interceptors import *

log = logging.getLogger(__name__)


class ProfileFactory:
    """Factory for profile creation"""

    @staticmethod
    def create_profile(
        profile_name: str, custom_cfg: Optional[Dict[str, Any]] = None
    ) -> List[BaseInterceptor]:
        """Create interceptors for a profile"""
        if custom_cfg:
            # Temporarily override configuration
            orig_cfg = config.config.copy()
            config._update_config(custom_cfg)

        # Get interceptors from configuration
        interceptors = config.create_interceptors(profile_name)

        if custom_cfg:
            # Restore original configuration
            config.config = orig_cfg

        return interceptors

    @staticmethod
    def create_default_profile() -> List[BaseInterceptor]:
        """Create default profile"""
        return [DataForwardingInterceptor()]

    @staticmethod
    def create_stealth_profile(
        encryption_key: str = "default-key-change-me",
    ) -> List[BaseInterceptor]:
        """Create stealth profile with maximum obfuscation"""
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
    def create_http_profile() -> List[BaseInterceptor]:
        """Create HTTP camouflage profile"""
        return [
            HTTPCamouflageInterceptor(),
            ObfuscationInterceptor(),
            EntropyAdjustmentInterceptor(),
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_tls_profile() -> List[BaseInterceptor]:
        """Create TLS camouflage profile"""
        return [
            TLSCamouflageInterceptor(),
            ObfuscationInterceptor(),
            EntropyAdjustmentInterceptor(),
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_video_profile() -> List[BaseInterceptor]:
        """Create video camouflage profile"""
        return [
            VideoCamouflageInterceptor(),
            ObfuscationInterceptor(),
            EntropyAdjustmentInterceptor(),
            DataForwardingInterceptor(),
        ]

    @staticmethod
    def create_speed_profile() -> List[BaseInterceptor]:
        """Create high-speed profile"""
        return [
            ObfuscationInterceptor(),
            ZeroCopyInterceptor(),
            DataForwardingInterceptor(),
        ]
