import errno
import logging
import select
import socket
from typing import Optional, Tuple, List

from src.core.context import ProtocolContext
from src.core.chain import InterceptorChain, Operation
from src.utils import *


class BaseProxy:
    """Base class for proxy operations"""

    def __init__(
        self,
        interceptors: Optional[List] = None,
        buffer_size=MAX_BUFFER_SIZE,
    ):
        self.interceptors = interceptors or []
        self.running = False
        self.clients = set()  # Track active clients
        self.chain = InterceptorChain(self.interceptors)
        self.MAX_BUFFER = buffer_size

    def stop(self):
        """Stop the proxy"""
        log.info("Stopping proxy...")
        self.running = False
        for sock in self.clients.copy():
            close_socket(sock)
