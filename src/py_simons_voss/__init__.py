"""
Simons Voss Gateway Communication Library.

This library provides TCP/IP communication capabilities for Simons Voss gateway.
"""

from .client import GatewayNode, GatewayConnectionError
from .exceptions import AuthenticationError, GatewayClientError

__all__ = [
    "GatewayNode",
    "GatewayClientError",
    "GatewayConnectionError",
    "AuthenticationError",
]
