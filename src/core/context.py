import socket
from dataclasses import dataclass, field
from typing import Any, Optional, Dict


@dataclass
class ProtocolContext:
    """Protocol context object"""

    client_socket: socket.socket  # client socket
    remote_socket: Optional[socket.socket] = None  # remote socket
    request_data: bytes = b""  # original request data
    processed_request: bytes = b""  # processed request data
    response_data: bytes = b""  # original response data
    processed_response: bytes = b""  # processed response data
    metadata: Dict[str, Any] = field(default_factory=dict)  # extend meta data
    should_drop: bool = False  # should drop the connection
    dest_addr: Optional[str] = None
    dest_port: Optional[int] = None
    protocol_stage: str = "init"  # Track stage (init, handshake, connect, transfer)
    error: Optional[Exception] = None  # Track errors
