import os
import yaml
import json
import logging
from typing import Dict, Any, List, Optional, Type
import importlib

from src.core import BaseInterceptor

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Configuration loader for PhantomSocket."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.

        Args:
            config_path: Path to the configuration file (YAML or JSON)
        """
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
            "profiles": {
                "default": {
                    "interceptors": [
                        {
                            "name": "DataForwardingInterceptor",
                            "enabled": True,
                        }
                    ]
                }
            },
            "active_profile": "default",
        }

        if config_path:
            self.load_config(config_path)

    def load_config(self, config_path: str) -> bool:
        """
        Load configuration from file.

        Args:
            config_path: Path to the configuration file

        Returns:
            bool: True if loaded successfully, False otherwise
        """
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return False

        try:
            file_extension = os.path.splitext(config_path)[1].lower()

            if file_extension in (".yaml", ".yml"):
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f)
            elif file_extension in (".json"):
                with open(config_path, "r") as f:
                    config = json.load(f)
            else:
                logger.error(f"Unsupported configuration file format: {file_extension}")
                return False

            # Update configuration
            self._update_config(config)
            logger.info(f"Configuration loaded from {config_path}")
            return True

        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False

    def _update_config(self, new_config: Dict[str, Any]):
        """
        Update configuration with new values.

        Args:
            new_config: New configuration dictionary
        """
        for section, values in new_config.items():
            if section in self.config:
                if isinstance(values, dict) and isinstance(self.config[section], dict):
                    # Deep update for nested dictionaries
                    self._deep_update(self.config[section], values)
                else:
                    # Direct update for simple values
                    self.config[section] = values
            else:
                # Add new section
                self.config[section] = values

    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]):
        """
        Deep update a nested dictionary.

        Args:
            target: Target dictionary to update
            source: Source dictionary with new values
        """
        for key, value in source.items():
            if (
                key in target
                and isinstance(value, dict)
                and isinstance(target[key], dict)
            ):
                # Recursively update nested dictionaries
                self._deep_update(target[key], value)
            else:
                # Update or add the key-value pair
                target[key] = value

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            section: Configuration section
            key: Configuration key (if None, returns the entire section)
            default: Default value if key not found

        Returns:
            Any: Configuration value
        """
        if section not in self.config:
            return default

        if key is None:
            return self.config[section]

        if isinstance(self.config[section], dict) and key in self.config[section]:
            return self.config[section][key]

        return default

    def set(self, section: str, key: str, value: Any):
        """
        Set a configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            value: Configuration value
        """
        if section not in self.config:
            self.config[section] = {}

        self.config[section][key] = value

    def get_active_profile(self) -> str:
        """
        Get the active profile name.

        Returns:
            str: Active profile name
        """
        return self.config.get("active_profile", "default")

    def set_active_profile(self, profile_name: str):
        """
        Set the active profile.

        Args:
            profile_name: Profile name
        """
        if profile_name in self.config.get("profiles", {}):
            self.config["active_profile"] = profile_name
        else:
            logger.warning(f"Profile '{profile_name}' not found, using default")
            self.config["active_profile"] = "default"

    def get_profile_interceptors(
        self, profile_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get interceptor configurations for a profile.

        Args:
            profile_name: Profile name (if None, uses active profile)

        Returns:
            List[Dict[str, Any]]: List of interceptor configurations
        """
        if profile_name is None:
            profile_name = self.get_active_profile()

        profiles = self.config.get("profiles", {})
        profile = profiles.get(
            profile_name, profiles.get("default", {"interceptors": []})
        )

        return profile.get("interceptors", [])

    def create_interceptors(
        self, profile_name: Optional[str] = None
    ) -> List[BaseInterceptor]:
        """
        Create interceptor instances from configuration.

        Args:
            profile_name: Profile name (if None, uses active profile)

        Returns:
            List[BaseInterceptor]: List of interceptor instances
        """
        interceptor_configs = self.get_profile_interceptors(profile_name)
        interceptors = []

        for config in interceptor_configs:
            if not config.get("enabled", True):
                continue

            interceptor_name = config.get("name")
            options = config.get("options", {})

            if not interceptor_name:
                continue

            try:
                # Try to find the interceptor class in the interceptors module
                interceptor_class = self._get_interceptor_class(interceptor_name)
                if interceptor_class is None:
                    logger.warning(f"Interceptor '{interceptor_name}' not found")
                    continue

                # Create instance with options
                if options:
                    interceptor = interceptor_class(**options)
                else:
                    interceptor = interceptor_class()

                interceptors.append(interceptor)
                logger.debug(f"Added interceptor: {interceptor_name}")

            except Exception as e:
                logger.error(f"Error creating interceptor '{interceptor_name}': {e}")

        return interceptors

    def _get_interceptor_class(
        self, class_name: str
    ) -> Optional[Type[BaseInterceptor]]:
        """
        Get interceptor class by name.

        Args:
            class_name: Interceptor class name

        Returns:
            Optional[Type[BaseInterceptor]]: Interceptor class or None if not found
        """
        # Search in all interceptor modules
        modules_to_check = [
            "src.interceptors.protocol",
            "src.interceptors.security",
            "src.interceptors.camouflage",
            "src.interceptors.analysis",
            "src.interceptors.optimize",
        ]

        for module_name in modules_to_check:
            try:
                module = importlib.import_module(module_name)
                if hasattr(module, class_name):
                    return getattr(module, class_name)
            except (ImportError, AttributeError):
                continue

        return None

    def save_config(self, config_path: str) -> bool:
        """
        Save configuration to file.

        Args:
            config_path: Path to the configuration file

        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            file_extension = os.path.splitext(config_path)[1].lower()

            if file_extension in (".yaml", ".yml"):
                with open(config_path, "w") as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            elif file_extension in (".json"):
                with open(config_path, "w") as f:
                    json.dump(self.config, f, indent=2)
            else:
                logger.error(f"Unsupported configuration file format: {file_extension}")
                return False

            logger.info(f"Configuration saved to {config_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False

    def update_from_args(self, args):
        """
        Update configuration from command-line arguments.

        Args:
            args: Command-line arguments namespace
        """
        # Update server configuration
        if hasattr(args, "host") and args.host:
            self.set("server", "host", args.host)

        if hasattr(args, "port") and args.port:
            self.set("server", "port", args.port)

        # Update local proxy configuration
        if hasattr(args, "local_host") and args.local_host:
            self.set("local", "host", args.local_host)

        if hasattr(args, "local_port") and args.local_port:
            self.set("local", "port", args.local_port)

        if hasattr(args, "server_host") and args.server_host:
            self.set("local", "server_host", args.server_host)

        if hasattr(args, "server_port") and args.server_port:
            self.set("local", "server_port", args.server_port)

        # Update general configuration
        if hasattr(args, "verbose") and args.verbose:
            self.set("general", "verbose", True)
            self.set("general", "log_level", "DEBUG")

        # Update active profile
        if hasattr(args, "profile") and args.profile:
            self.set_active_profile(args.profile)

# Create a singleton instance
config = ConfigLoader()