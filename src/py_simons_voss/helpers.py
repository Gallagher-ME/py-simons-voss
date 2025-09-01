"""Helper methods for Simons Voss gateway communication."""


def normalize_address(address: int | str) -> int:
    """
    Parse and validate a device address as a 4-byte unsigned integer.

        Rules:
        - Accepts values like 100 or "100" and interprets them as hex digits -> 0x00000100 (256).
        - Accepts hex like 0x00000100 or "0x00000100" and returns the integer value.
        - Raises ValueError if the result is negative, exceeds 4 bytes (0xFFFFFFFF),
            or is all zeros (0x00000000) or all ones (0xFFFFFFFF).

    Returns:
        int: The normalized integer address.
    """
    # Parse inputs
    if isinstance(address, str):
        s = address.strip()
        try:
            # If it starts with 0x, parse as hex; otherwise interpret digits as hex
            if s.lower().startswith("0x"):
                value = int(s, 16)
            else:
                value = int(s, 16)
        except Exception as exc:
            raise ValueError(f"Invalid address string: {address!r}") from exc
    elif isinstance(address, int):
        # Interpret bare integers as hex digits as well (e.g., 100 -> 0x100)
        try:
            value = int(str(address), 16)
        except Exception as exc:
            raise ValueError(f"Invalid address integer: {address!r}") from exc
    else:
        raise ValueError(f"Address must be int or str, got {type(address).__name__}")

    # Validate range and reserved values
    if value <= 0 or value > 0xFFFFFFFF or value == 0xFFFFFFFF:
        raise ValueError("Address must be 1..0xFFFFFFFE and fit in 4 bytes")

    return value


def mask_ref_id(ref_id: int) -> int:
    """Mask the reference ID to 6 bits."""
    return ref_id & 0x3F


def calculate_crc(data: bytes) -> int:
    """Calculate CRC-16/CCITT checksum."""
    POLYNOMIAL = 0x1021
    INITIAL_VALUE = 0x0000

    crc = INITIAL_VALUE
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ POLYNOMIAL
            else:
                crc <<= 1
    return crc & 0xFFFF
