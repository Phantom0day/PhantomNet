import socket
from dataclasses import dataclass, field
from typing import Any, Optional, Dict
from .operation import Operation


@dataclass
class ProtocolContext:
    """Protocol context object"""

    data: bytes = b""
    meta: Dict[str, Any] = field(default_factory=dict)
    drop: bool = False
    stage: str = "init"
    operation: Operation = None
    error: Optional[Exception] = None
