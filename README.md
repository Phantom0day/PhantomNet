# PhantomSocket

A modular, robust SOCKS5 proxy implementation inspired by Shadowsocks.

## Features

- Full SOCKS5 protocol implementation
- Modular design with separate server and client components
- Robust error handling and logging
- Easy to extend with additional features
- Clean separation of concerns for maintainability

## Project Structure

```
phantomsocket/
├── __init__.py               # Package definition
├── common/                   # Shared components
│   ├── __init__.py
│   ├── constants.py          # Protocol constants
│   └── utils.py              # Utility functions
├── server/                   # Server implementation
│   ├── __init__.py
│   └── socks5_server.py      # SOCKS5 server
├── client/                   # Client implementation
│   ├── __init__.py
│   ├── socks5_client.py      # SOCKS5 client
│   └── local_proxy.py        # Local client proxy
└── main.py                   # CLI entry point
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Phantom0day/PhantomSocket.git
cd PhantomSocket
```

2. Install (optional):

```bash
pip install -e .
```

## Usage

### Running the SOCKS5 Server

```bash
python -m phantomsocket.main server --host 0.0.0.0 --port 8080
```

### Running the Local Client Proxy

```bash
python -m phantomsocket.main client --server-host YOUR_SERVER_IP --server-port 8080
```

### Command-line Options

Server mode:
- `--host`: Server bind address (default: 0.0.0.0)
- `--port`: Server bind port (default: 8080)

Client mode:
- `--local-host`: Local bind address (default: 127.0.0.1)
- `--local-port`: Local bind port (default: 1080)
- `--server-host`: Remote SOCKS5 server address
- `--server-port`: Remote SOCKS5 server port (default: 8080)

## Configuring Applications

To use applications with the local proxy:

1. Configure your browser or application to use a SOCKS5 proxy:
   - Host: 127.0.0.1 (or the value of `--local-host`)
   - Port: 1080 (or the value of `--local-port`)

2. For Firefox:
   - Go to Settings → General → Network Settings
   - Choose "Manual proxy configuration"
   - Enter the SOCKS host (127.0.0.1) and port (1080)
   - Select SOCKS v5

3. For Chrome/Edge:
   - Go to Settings → Advanced → System → Proxy settings
   - Enable manual proxy configuration
   - Set SOCKS host and port
   - Select SOCKS v5

## Future Enhancements

- Add encryption between client and server
- Implement user authentication
- Add UDP support
- Add traffic statistics and monitoring
- Add configuration file support

## License

MIT License

## Acknowledgments

This project was inspired by Shadowsocks and the SOCKS5 protocol (RFC 1928).