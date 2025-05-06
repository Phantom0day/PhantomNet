# PhantomSocket

A modular SOCKS5 proxy implementation with interceptor chain architecture designed for network censorship circumvention.

## Overview

PhantomSocket is a specialized framework designed to bypass network censorship using various obfuscation and camouflage techniques. It consists of two main components:

1. **Local Client Proxy**: Runs on the user's machine and accepts SOCKS5 connections from local applications
2. **Remote Server**: Receives connections from the local proxy and forwards them to the actual destinations

The framework uses a responsibility chain pattern similar to OkHttp's interceptor design, allowing easy addition of middleware components to handle protocol obfuscation, encryption, and other transformations.

## Architecture

```
+-------------+      +----------------+      +------------------+
| Local App   | ---> | Local Proxy    | ---> | Remote Server    | ---> Internet
| (Browser)   | <--- | (SOCKS5 Server)| <--- | (Custom Protocol)| <---
+-------------+      +----------------+      +------------------+
                       |         ^                |        ^
                       v         |                v        |
                    +-------------------------------+
                    | Interceptor Chain (Transform) |
                    +-------------------------------+
```

The interceptor chain allows modification of both requests and responses passing through either component:

1. Each request passes through the interceptor chain before being sent
2. Each response passes through the interceptor chain before being forwarded back
3. Interceptors on the client and server sides should complement each other (e.g., if the client encrypts, the server should decrypt)

## Installation

```bash
# Clone the repository
git clone https://github.com/Phantom0day/PhantomSocket.git
cd PhantomSocket

# Install the package
pip install -e .
```

## Usage

### Running the Remote Server

```bash
python run.py server --host 0.0.0.0 --port 8388
```

### Running the Local Client Proxy

```bash
python run.py local --local-port 1080 --server-host your-server-ip --server-port 8388
```

### Using the Proxy with Applications

Configure your applications to use a SOCKS5 proxy with:
- Host: 127.0.0.1
- Port: 1080 (or whatever port you specified for --local-port)
- No authentication

## Adding Custom Interceptors

PhantomSocket's power lies in its extensibility. Create custom interceptors by subclassing `BaseInterceptor`:

```python
from src.core import ProtocolContext
from src.interceptors.core import BaseInterceptor

class MyCustomInterceptor(BaseInterceptor):
    def pack(self, context: ProtocolContext) -> ProtocolContext:
        # Modify outgoing request
        context.processed_request = transform(context.request_data)
        return context
        
    def unpack(self, context: ProtocolContext) -> ProtocolContext:
        # Modify incoming response
        context.processed_response = transform(context.response_data)
        return context
```

Then add your interceptor to the chain in your server and client:

```python
# For the client
local_proxy = LocalClientProxy(
    "127.0.0.1", 
    1080, 
    "your-server-ip", 
    8388,
    interceptors=[
        MyEncryptionInterceptor(),
        MyObfuscationInterceptor()
    ]
)

# For the server
server = RemoteServer(
    "0.0.0.0", 
    8388,
    interceptors=[
        MyDecryptionInterceptor(),
        MyDeobfuscationInterceptor()
    ]
)
```

## Included Interceptor Categories

PhantomSocket includes several interceptor categories that you can implement:

### Security Interceptors
- Encryption/decryption of traffic
- Protocol obfuscation
- Packet size normalization

### Camouflage Interceptors
- Traffic disguised as HTTP/HTTPS
- Traffic disguised as TLS
- Traffic disguised as video streaming

### Analysis Evasion Interceptors
- DPI (Deep Packet Inspection) evasion
- Entropy adjustment
- Timing randomization

### Optimization Interceptors
- Connection pooling
- Performance optimizations

## Security Considerations

- The default implementation (without interceptors) provides **no security** - all traffic is sent in plaintext
- Add appropriate interceptors for encryption and obfuscation based on your threat model
- Always use strong encryption for sensitive traffic

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for legitimate privacy protection and censorship circumvention. Users are responsible for complying with local laws and regulations.