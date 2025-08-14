"""
Simons Voss Gateway Communication Library.

This library provides TCP/IP communication capabilities for Simons Voss gateway.
"""

from .client import (
    ClientSocket,
    GatewayClientError,
    GatewayConnectionError,
    AuthenticationError,
)

__all__ = [
    "ClientSocket",
    "GatewayClientError",
    "GatewayConnectionError",
    "AuthenticationError",
]
