import os
import yaml
import json
import logging
from typing import Dict, Any, List, Optional, Type
import importlib

from src.interceptors import BaseInterceptor
from src.utils import *


class ConfigLoader:
    """Configuration loader"""

    def __init__(self, config_path: Optional[str] = None):
        # Default configuration
        self.config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8388,
                "max_connections": 100,
                "timeout": 300,
            },
            "local": {
                "host": "127.0.0.1",
                "port": 1080,
                "server_host": None,
                "server_port": 8388,
                "timeout": 300,
            },
            "general": {
                "log_level": "INFO",
                "log_file": None,
                "verbose": False,
            },
            "profiles": {"default": {"interceptors": []}},
            "active_profile": "default",
        }

        if config_path:
            self.load_config(config_path)

    def load_config(self, path: str) -> bool:
        """Load configuration from file"""
        if not os.path.exists(path):
            log.error(f"Config file not found: {path}")
            return False

        try:
            ext = os.path.splitext(path)[1].lower()

            if ext in (".yaml", ".yml"):
                with open(path, "r") as f:
                    cfg = yaml.safe_load(f)
            elif ext in (".json"):
                with open(path, "r") as f:
                    cfg = json.load(f)
            else:
                log.error(f"Unsupported config file format: {ext}")
                return False

            self._update_config(cfg)
            log.info(f"Config loaded from {path}")
            return True

        except Exception as e:
            log.error(f"Error loading config: {e}")
            return False

    def _update_config(self, new_cfg: Dict[str, Any]):
        """Update configuration with new values"""
        for section, values in new_cfg.items():
            if section in self.config:
                if isinstance(values, dict) and isinstance(self.config[section], dict):
                    self._deep_update(self.config[section], values)
                else:
                    self.config[section] = values
            else:
                # Add new section
                self.config[section] = values

    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Deep update a nested dictionary"""
        for k, v in source.items():
            if k in target and isinstance(v, dict) and isinstance(target[k], dict):
                # Recursively update nested dictionaries
                self._deep_update(target[k], v)
            else:
                # Update or add the key-value pair
                target[k] = v

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get configuration value"""
        if section not in self.config:
            return default

        if key is None:
            return self.config[section]

        return (
            self.config[section].get(key, default)
            if isinstance(self.config[section], dict)
            else default
        )

    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}

        if key:
            self.config[section][key] = value
        else:
            self.config[section] = value

    def get_active_profile(self) -> str:
        """Get active profile name"""
        return self.config.get("active_profile", "default")

    def set_active_profile(self, profile: str):
        """Set active profile"""
        if profile in self.config.get("profiles", {}):
            self.config["active_profile"] = profile
        else:
            log.warning(f"Profile '{profile}' not found, using default")
            self.config["active_profile"] = "default"

    def get_profile_interceptors(
        self, profile: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get interceptor configs for a profile"""
        if profile is None:
            profile = self.get_active_profile()

        profiles = self.config.get("profiles", {})
        profile = profiles.get(profile, profiles.get("default", {"interceptors": []}))

        return profile.get("interceptors", [])

    def create_interceptors(
        self, profile: Optional[str] = None
    ) -> List[BaseInterceptor]:
        """Create interceptor instances from configuration"""
        configs = self.get_profile_interceptors(profile)
        interceptors = []

        for cfg in configs:
            if not cfg.get("enabled", True):
                continue

            name = cfg.get("name")
            opts = cfg.get("options", {})

            if not name:
                continue

            try:
                cls = self._get_interceptor_class(name)
                if cls is None:
                    log.warning(f"Interceptor '{name}' not found")
                    continue

                interceptor = cls(**opts) if opts else cls()
                interceptors.append(interceptor)
                log.debug(f"Added interceptor: {name}")

            except Exception as e:
                log.error(f"Error creating interceptor '{name}': {e}")

        return interceptors

    def _get_interceptor_class(
        self, class_name: str
    ) -> Optional[Type[BaseInterceptor]]:
        """Get interceptor class by name"""
        modules = [
            "src.interceptors",
        ]

        for mod_name in modules:
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, class_name):
                    return getattr(mod, class_name)
            except (ImportError, AttributeError):
                continue

        return None

    def save_config(self, path: str) -> bool:
        """Save configuration to file"""
        try:
            ext = os.path.splitext(path)[1].lower()

            if ext in (".yaml", ".yml"):
                with open(path, "w") as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            elif ext in (".json"):
                with open(path, "w") as f:
                    json.dump(self.config, f, indent=2)
            else:
                log.error(f"Unsupported config file format: {ext}")
                return False

            log.info(f"Config saved to {path}")
            return True

        except Exception as e:
            log.error(f"Error saving config: {e}")
            return False

    def update_from_args(self, args):
        """Update configuration from command-line arguments"""
        # Server config
        if hasattr(args, "host") and args.host:
            self.set("server", "host", args.host)

        if hasattr(args, "port") and args.port:
            self.set("server", "port", args.port)

        # Local proxy config
        if hasattr(args, "local_host") and args.local_host:
            self.set("local", "host", args.local_host)

        if hasattr(args, "local_port") and args.local_port:
            self.set("local", "port", args.local_port)

        if hasattr(args, "server_host") and args.server_host:
            self.set("local", "server_host", args.server_host)

        if hasattr(args, "server_port") and args.server_port:
            self.set("local", "server_port", args.server_port)

        # General config
        if hasattr(args, "verbose") and args.verbose:
            self.set("general", "verbose", True)
            self.set("general", "log_level", "DEBUG")

        # Active profile
        if hasattr(args, "profile") and args.profile:
            self.set_active_profile(args.profile)


# Create a singleton instance
config = ConfigLoader()
