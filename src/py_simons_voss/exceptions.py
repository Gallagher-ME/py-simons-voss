"""Exceptions for the Simons Voss client and device operations."""


class SimonsVossError(Exception):
    """Base exception for Simons Voss client and device errors."""


class AddressMismatchError(SimonsVossError):
    """Exception raised for address mismatches in Simons Voss messages."""


class MsgDecodeError(SimonsVossError):
    """Exception raised when a message cannot be decoded."""


class GatewayClientError(SimonsVossError):
    """Base exception for gateway client errors."""


class GatewayConnectionError(GatewayClientError):
    """Raised when connection to gateway fails."""


class AuthenticationError(GatewayClientError):
    """Raised when AES authentication fails."""


class GatewayNotAvailable(GatewayClientError):
    """Raised when the gateway does not respond to GET_STATUS during connect()."""
