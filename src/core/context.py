import socket
from dataclasses import dataclass, field
from typing import Any, Optional, Dict


@dataclass
class ProtocolContext:
    """Protocol context object"""

    client: Optional[socket.socket] = None
    remote: Optional[socket.socket] = None
    req_data: bytes = b""
    resp_data: bytes = b""
    meta: Dict[str, Any] = field(default_factory=dict)
    drop: bool = False
    dest_addr: Optional[str] = None
    dest_port: Optional[int] = None
    stage: str = "init"
    error: Optional[Exception] = None
