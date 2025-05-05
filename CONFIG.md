# PhantomSocket Configuration System

PhantomSocket includes a flexible configuration system that allows you to customize the proxy behavior through:

1. Configuration files (YAML or JSON)
2. Command-line arguments
3. Programmatic API

## Configuration Files

PhantomSocket looks for configuration files in the following locations:

1. Path specified with the `--config` command-line option
2. `./config.yaml` in the current directory
3. `./config.yml` in the current directory
4. `./config.json` in the current directory
5. `~/.phantomsocket/config.yaml` in the user's home directory
6. `/etc/phantomsocket/config.yaml` at the system level

### Example Configuration

```yaml
# Server configuration
server:
  host: 0.0.0.0
  port: 8388
  max_connections: 100
  timeout: 300  # seconds

# Local proxy configuration
local:
  host: 127.0.0.1
  port: 1080
  server_host: example.com
  server_port: 8388
  timeout: 300  # seconds

# General settings
general:
  log_level: INFO
  log_file: null  # null means log to stdout
  verbose: false

# Default active profile
active_profile: stealth

# Interceptor profiles
profiles:
  # Different profiles for different scenarios
  default:
    interceptors:
      - name: DataForwardingInterceptor
        enabled: true
  
  # Stealth profile for maximum censorship evasion
  stealth:
    interceptors:
      - name: AESEncryptionInterceptor
        enabled: true
        options:
          key: "your-secure-key-here"
      
      - name: HTTPCamouflageInterceptor
        enabled: true
      
      - name: EntropyAdjustmentInterceptor
        enabled: true
      
      - name: TimingInterceptor
        enabled: true
      
      - name: DataForwardingInterceptor
        enabled: true
```

## Profiles

Profiles are collections of interceptors with specific configurations. PhantomSocket includes several built-in profiles:

1. **default** - Basic functionality with minimal interceptors
2. **stealth** - Maximum censorship evasion with multiple layers of obfuscation
3. **http_camouflage** - Disguises traffic as HTTP
4. **tls_camouflage** - Disguises traffic as TLS/HTTPS
5. **high_speed** - Optimized for speed with minimal obfuscation

You can select a profile using the `--profile` command-line option or by setting the `active_profile` in the configuration file.

## Command-line Configuration Tool

PhantomSocket includes a configuration tool (`config_tool.py`) for managing configurations:

### Create a new configuration

```bash
python config_tool.py create config.yaml --profile stealth
```

### Edit a configuration

```bash
python config_tool.py edit config.yaml --set "local.server_host=example.com" --profile http_camouflage
```

### Show configuration

```bash
# Show entire configuration
python config_tool.py show config.yaml

# List available profiles
python config_tool.py show config.yaml --list-profiles

# Show specific profile
python config_tool.py show config.yaml --profile stealth

# Get specific setting
python config_tool.py show config.yaml --get server.port
```

## Command-line Arguments

You can override configuration settings with command-line arguments:

```bash
# Run server with specific host and port
python run.py server --host 0.0.0.0 --port 8388 --profile stealth

# Run local proxy with specific settings
python run.py local --local-port 1080 --server-host example.com --server-port 8388 --profile http_camouflage
```

## Programmatic API

You can also use the configuration system programmatically:

```python
from src.config import ConfigLoader
from src.client import LocalClientProxy
from src.server import RemoteServer

# Load configuration
config = ConfigLoader("config.yaml")

# Get configuration values
server_host = config.get("server", "host")
server_port = config.get("server", "port")

# Set configuration values
config.set("local", "server_host", "example.com")
config.set_active_profile("stealth")

# Create interceptors from active profile
interceptors = config.create_interceptors()

# Create server or client with the interceptors
server = RemoteServer(server_host, server_port, interceptors)
```

## Creating Custom Profiles

You can create custom profiles in your configuration file:

```yaml
profiles:
  my_custom_profile:
    interceptors:
      - name: AESEncryptionInterceptor
        enabled: true
        options:
          key: "my-custom-key"
      
      - name: HTTPCamouflageInterceptor
        enabled: true
      
      # Add more interceptors as needed
```

Or use the ProfileFactory programmatically:

```python
from src.config import ProfileFactory

# Create a profile with specific interceptors
interceptors = ProfileFactory.create_stealth_profile(encryption_key="my-secure-key")

# Use the interceptors with server or client
server = RemoteServer("0.0.0.0", 8388, interceptors)
```

## Developing Custom Interceptors

When developing custom interceptors, you can easily integrate them with the configuration system:

1. Create your interceptor class inheriting from `BaseInterceptor`
2. Add your interceptor to the appropriate module (security, camouflage, etc.)
3. Add it to your configuration profile

```python
from src.core import BaseInterceptor, ProtocolContext

class MyCustomInterceptor(BaseInterceptor):
    def __init__(self, custom_option="default"):
        self.custom_option = custom_option
    
    def pre_process(self, context: ProtocolContext) -> ProtocolContext:
        # Custom pre-processing logic
        return context
    
    def post_process(self, context: ProtocolContext) -> ProtocolContext:
        # Custom post-processing logic
        return context
```

Then add it to your configuration:

```yaml
profiles:
  custom_profile:
    interceptors:
      - name: MyCustomInterceptor
        enabled: true
        options:
          custom_option: "my-value"
```