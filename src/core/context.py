from dataclasses import dataclass, field
from typing import Any, Optional, Dict
from .operation import Operation
from src.stream import *


@dataclass
class ProtocolContext:
    """Protocol context object"""

    # --- data layer ---
    data: bytes = b""
    # data frame
    frame_type: int = FrameType.SOCKS
    channel_id: int = 0
    # --- business layer
    meta: Dict[str, Any] = field(default_factory=dict)
    drop: bool = False
    stage: str = "init"
    operation: Operation = None
    error: Optional[Exception] = None
