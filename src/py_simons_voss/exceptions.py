"""Exceptions for the Simons Voss client and device operations."""


class SimonsVossError(Exception):
    """Base exception for Simons Voss client and device errors."""


class AddressMismatchError(SimonsVossError):
    """Exception raised for address mismatches in Simons Voss messages."""


class MsgDecodeError(SimonsVossError):
    """Exception raised when a message cannot be decoded."""
