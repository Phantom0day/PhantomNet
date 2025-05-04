import os
import json
import yaml
import logging
import configparser
from typing import Dict, Any

from src.common import constants as const

logger = logging.getLogger(__name__)


class Config:
    """Configuration handler for PhantomSocket."""

    def __init__(self, config_file=None):
        """
        Initialize configuration.

        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        self.config = {
            const.KEY_MODE: None,
            const.KEY_SERVER: {
                const.KEY_HOST: const.NONSPEC_HOST,
                const.KEY_PORT: const.DEFAULT_SERVER_PORT,
                const.KEY_AUTH: "none",
                const.KEY_AUTH_FILE: None,
            },
            const.KEY_CLIENT: {
                const.KEY_LOCAL_HOST: const.LOCAL_HOST,
                const.KEY_LOCAL_PORT: const.DEFAULT_LOCAL_PORT,
                const.KEY_SERVER_HOST: None,
                const.KEY_SERVER_PORT: const.DEFAULT_SERVER_PORT,
            },
            const.KEY_LOG: {
                "level": "INFO",
                "format": const.DEFAULT_LOGGING_FORMAT,
                "file": None,
            },
            const.KEY_POOL: {
                const.KEY_MAX_SIZE: 100,
                const.KEY_DNS_CACHE_TTL: 300,
                const.KEY_DNS_SERVERS: const.DEFAULT_DNS_SERVERS,
                const.KEY_DISABLE_DNS_CACHE: False,
                const.KEY_DNS_TIMEOUT: const.DEFAULT_DNS_TIMEOUT,
                const.KEY_DNS_RETRIES: 3,
            },
        }
        if config_file:
            self.load_config(config_file)

    def load_config(self, config_file):
        """
        Load configuration from file.

        Args:
            config_file: Path to configuration file

        Returns:
            bool: True if loaded successfully
        """
        if not os.path.exists(config_file):
            logger.error(f"Configuration file not found: {config_file}")
            return False

        file_ext = os.path.splitext(config_file)[1].lower()

        try:
            if file_ext == ".json":
                self._load_json(config_file)
            elif file_ext in (".yaml", ".yml"):
                self._load_yaml(config_file)
            elif file_ext in (".ini", ".conf", ".cfg"):
                self._load_ini(config_file)
            else:
                logger.error(f"Unsupported configuration file format: {file_ext}")
                return False

            logger.info(f"Configuration loaded from {config_file}")
            return True
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False

    def _load_json(self, config_file):
        """Load JSON configuration."""
        with open(config_file, "r") as f:
            config = json.load(f)
            self._update_config(config)

    def _load_yaml(self, config_file):
        """Load YAML configuration."""
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
            self._update_config(config)

    def _load_ini(self, config_file):
        """Load INI configuration."""
        parser = configparser.ConfigParser()
        parser.read(config_file)

        config = {}

        # Convert ConfigParser object to dict
        for section in parser.sections():
            config[section] = {}
            for key, value in parser.items(section):
                # Try to convert string values to appropriate types
                try:
                    # Try to convert to int or float
                    if value.isdigit():
                        value = int(value)
                    elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
                        value = float(value)
                    # Convert boolean strings
                    elif value.lower() in ("true", "yes", "on"):
                        value = True
                    elif value.lower() in ("false", "no", "off"):
                        value = False
                except:
                    pass

                config[section][key] = value

        self._update_config(config)

    def _update_config(self, new_config):
        """
        Update configuration with new values.

        Args:
            new_config: New configuration dict
        """
        # Update mode
        if "mode" in new_config:
            self.config["mode"] = new_config["mode"]

        # Update server config
        self._update_config_key(const.KEY_SERVER, new_config)

        # Update client config
        self._update_config_key(const.KEY_CLIENT, new_config)

        # Update logging config
        self._update_config_key(const.KEY_LOG, new_config)

        # Update connection pool config
        self._update_config_key(const.KEY_POOL, new_config)

    def _update_config_key(self, key, new_config):
        if key in new_config:
            for subkey, value in new_config[key].items():
                if subkey in self.config[key]:
                    self.config[key][subkey] = value

    def validate(self):
        """Validate config values"""
        # validate server port
        server_port = self.get(const.KEY_SERVER, const.KEY_PORT)
        if not isinstance(server_port, int) or server_port < 1 or server_port > 65535:
            raise ValueError(f"Invalid server port: {server_port}")

        # validate connection pool maximum size
        max_size = self.get(const.KEY_POOL, const.KEY_MAX_SIZE)
        if not isinstance(max_size, int) or max_size < 1:
            raise ValueError(f"Invalid connection pool max_size: {max_size}")

        # validate DNS cache TTL
        dns_cache_ttl = self.get(const.KEY_POOL, const.KEY_DNS_CACHE_TTL)
        if not isinstance(dns_cache_ttl, int) or dns_cache_ttl < 0:
            raise ValueError(f"Invalid dns_cache_ttl: {dns_cache_ttl}")

    def get(self, section, key=None, default=None):
        """
        Get configuration value.

        Args:
            section: Configuration section
            key: Configuration key (if None, returns entire section)
            default: Default value if key not found

        Returns:
            Configuration value
        """
        if section not in self.config:
            return default

        if key is None:
            return self.config[section]

        return self.config[section].get(key, default)

    def set(self, section, key, value):
        """
        Set configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            value: Configuration value
        """
        if section not in self.config:
            self.config[section] = {}

        if key == None:
            self.config[section] = value
        else:
            self.config[section][key] = value

    def save_config(self, config_file=None):
        """
        Save configuration to file.

        Args:
            config_file: Path to configuration file (default: self.config_file)

        Returns:
            bool: True if saved successfully
        """
        if not config_file:
            config_file = self.config_file

        if not config_file:
            logger.error("No configuration file specified")
            return False

        file_ext = os.path.splitext(config_file)[1].lower()

        try:
            if file_ext == ".json":
                self._save_json(config_file)
            elif file_ext in (".yaml", ".yml"):
                self._save_yaml(config_file)
            elif file_ext in (".ini", ".conf", ".cfg"):
                self._save_ini(config_file)
            else:
                logger.error(f"Unsupported configuration file format: {file_ext}")
                return False

            logger.info(f"Configuration saved to {config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False

    def _save_json(self, config_file):
        """Save JSON configuration."""
        with open(config_file, "w") as f:
            json.dump(self.config, f, indent=4)

    def _save_yaml(self, config_file):
        """Save YAML configuration."""
        with open(config_file, "w") as f:
            yaml.dump(self.config, f, sort_keys=False)

    def _save_ini(self, config_file):
        """Save INI configuration."""
        parser = configparser.ConfigParser()

        # Convert dict to ConfigParser object
        for section, values in self.config.items():
            if not isinstance(values, dict):
                # Handle top-level keys
                if "general" not in parser:
                    parser["general"] = {}
                parser["general"][section] = str(values)
                continue

            parser[section] = {}
            for key, value in values.items():
                parser[section][key] = str(value)

        with open(config_file, "w") as f:
            parser.write(f)
