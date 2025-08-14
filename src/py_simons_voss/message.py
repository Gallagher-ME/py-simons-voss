"""
Message types and Message class for Simons Voss devices.

This module defines:
- MsgType: enumeration of message types
- Message: builder/decoder for the Simons Voss protocol messages
"""

from __future__ import annotations

import struct
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .device import Lock


class MsgType(Enum):
    """Enumeration of all available Simons Voss device message types."""

    # Command values
    RESPONSE = 0x00
    GET_STATUS = 0x01
    GET_SYSTEM_INFO = 0x02
    ADD_TO_WHITELIST = 0x03
    REMOVE_FROM_WHITELIST = 0x04
    DELETE_WHOLE_WHITELIST = 0x05
    DEACTIVATE_WHITELIST = 0x06
    ACTIVATE_WHITELIST = 0x07
    ACCESS_DENIED = 0x08
    SHORT_TERM_ACTIVATION = 0x09
    LONG_TERM_ACTIVATION = 0x0A
    LONG_TERM_RELEASE = 0x0B
    OFFICE_MODE_GRANT = 0x0C
    OFFICE_MODE_RELEASE = 0x0D
    READER_EVENT = 0x0E
    READER_INFO_EVENT = 0x0F
    DELETE_WHOLE_PRIORITY_WHITELIST = 0x10
    DOOR_MONITORING_EVENT = 0x11
    CARD_READER_STATE_EVENT = 0x12

    @classmethod
    def is_event(cls, msg_type: MsgType) -> bool:
        """Return True if the given MsgType (or int) is an event type."""
        return msg_type in [
            cls.READER_EVENT,
            cls.READER_INFO_EVENT,
            cls.DOOR_MONITORING_EVENT,
            cls.CARD_READER_STATE_EVENT,
        ]

    @classmethod
    def from_value(cls, value):
        """Find MsgType by value."""
        for msg_type in cls:
            if msg_type.value == value:
                return msg_type
        raise ValueError(f"Unknown message type: {value:02X}")


class ReferenceType(Enum):
    """Reference type for messages."""

    CMD_EVENT = 0x00
    ANSWER = 0x10


class Message:
    """
    Class for constructing and decoding Simons Voss device messages.

    This class handles both outgoing commands and incoming events with the correct
    message format including device address and live status.

    Message Structure:
    - Total Length (1 Byte) - length of entire message
    - ACP Identifier 0xFEFD (2 bytes, fixed)
    - Message Layer Length (1 Byte) - length of message layer without CRC
    - Message Layer Data:
      - Header version (1 Byte) always 0x01
      - User_Enc (1 Byte): 0x00 unencrypted, 0x01 encrypted
      - Unused Byte (1 Byte) always 0x00
      - Ref_ID Byte: bits 6-7 = '10' (value 2), bits 0-5 = fixed value
      - Sequence counter (4 Bytes)
      - Device Address (4 Bytes)
      - Msg_type (1 Byte), bit 7 is set when sending card reader event responses to device
      - Msg data (variable length based on message type)
      - Live status (5 bytes, only for specific message types)
    - CRC-16/CCITT (2 bytes)

    Note: Bit 7 of Msg_type is only set when sending messages TO the device as card reader responses.
    When decoding received messages FROM the device, bit 7 will not be set.
    """

    # Protocol constants
    ACP_IDENTIFIER = 0xFEFD
    HEADER_VERSION = 0x01
    UNENCRYPTED = 0x00
    ENCRYPTED = 0x01
    UNUSED_BYTE = 0x00
    LIVE_STATUS_LENGTH = 5

    def __init__(
        self,
        msg_type: MsgType,
        lock_address: int,
        ref_id: int,
        sequence_counter: int = 0,
        msg_data: bytes = b"",
        live_status: bytes = b"",
        encrypted: bool = False,
        is_card_reader_response: bool = False,
    ):
        """
        Initialize a message.

        Args:
            msg_type: The message type
            lock_address: Lock address (4 bytes)
            ref_id: Reference ID (int, bits 6-7 indicate type: 00=CMD/EVENT, 10=ANSWER)
            sequence_counter: Sequence counter value
            msg_data: Message data
            live_status: Live status data (5 bytes if present)
            encrypted: Whether the message is encrypted
            is_card_reader_response: Whether bit 7 should be set in command byte
        """
        self.msg_type = msg_type
        self.lock_address = lock_address
        self.sequence_counter = sequence_counter
        self.ref_id = ref_id & 0xFF  # Ensure it's within byte range

        # Derive type from bits 6-7 (00=CMD/EVENT, 10=ANSWER). Map unknown to CMD_EVENT
        type_bits = (self.ref_id >> 6) & 0x03
        if type_bits == 0x02:
            self.ref_id_type = ReferenceType.ANSWER
        else:
            self.ref_id_type = ReferenceType.CMD_EVENT

        self.msg_data = msg_data
        self.live_status = live_status
        self.encrypted = encrypted
        self.is_card_reader_response = is_card_reader_response

        # Calculate derived values
        self.msg_byte = msg_type.value
        if is_card_reader_response:
            self.msg_byte |= 0x80  # Set bit 7
        self.lock: Lock | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        """
        Decode a message from bytes.

        Args:
            data: Raw message bytes including total length byte and CRC

        Returns:
            Decoded Message instance

        Raises:
            ValueError: If message format is invalid or CRC check fails
        """
        if len(data) < 15:  # Minimum message size with new structure
            raise ValueError(f"Message too short: {len(data)} bytes")

        # Extract total length byte
        total_length = data[0]
        if len(data) != total_length:
            raise ValueError(
                f"Length mismatch: expected {total_length}, got {len(data)}"
            )

        # Extract ACP identifier
        acp_id = struct.unpack(">H", data[1:3])[0]
        if acp_id != cls.ACP_IDENTIFIER:
            raise ValueError(
                f"Invalid ACP identifier: expected {cls.ACP_IDENTIFIER:04X}, got {acp_id:04X}"
            )

        # Extract message layer length
        message_layer_length = data[3]

        # The message layer length includes itself in the count
        # So the actual message layer data is (message_layer_length - 1) bytes
        # Structure: [total_length][ACP_ID][msg_layer_length][message_layer_data][CRC]
        # Where message_layer_data is (message_layer_length - 1) bytes

        message_layer_start = 4  # After total_length + ACP + msg_layer_length
        message_layer_data_length = (
            message_layer_length - 1
        )  # Subtract the length byte itself
        message_layer_end = message_layer_start + message_layer_data_length

        # The total length byte represents the entire message length including itself
        # Structure: 1 (total_length) + 2 (ACP) + message_layer_length + 2 (CRC) should equal total_length
        expected_total_from_structure = 1 + 2 + message_layer_length + 2
        if expected_total_from_structure != total_length:
            raise ValueError(
                f"Message structure invalid: calculated total length {expected_total_from_structure}, but total length byte says {total_length}"
            )

        message_layer = data[message_layer_start:message_layer_end]

        # Verify CRC - CRC is calculated over the entire message except the CRC itself
        # This includes: total_length + ACP + msg_layer_length + message_layer_data
        message_without_crc = data[:-2]  # Everything except the last 2 CRC bytes
        received_crc = struct.unpack(
            ">H", data[message_layer_end : message_layer_end + 2]
        )[0]
        calculated_crc = cls._calculate_crc16_ccitt(message_without_crc)

        if received_crc != calculated_crc:
            raise ValueError(
                f"CRC mismatch: expected {calculated_crc:04X}, got {received_crc:04X}"
            )

        # Parse message layer (minimum 13 bytes: header + user_enc + unused + ref_id + sequence + device_addr + msg_type)
        if len(message_layer) < 13:
            raise ValueError(f"Message layer too short: {len(message_layer)} bytes")

        # Parse header
        (
            header_version,
            user_enc,
            unused_byte,
            ref_id,
            sequence_counter,
            lock_address,
            msg_type_byte,
        ) = struct.unpack(">B B B B I I B", message_layer[:13])

        # Validate header
        if header_version != cls.HEADER_VERSION:
            raise ValueError(
                f"Invalid header version: expected {cls.HEADER_VERSION}, got {header_version}"
            )

        if unused_byte != cls.UNUSED_BYTE:
            raise ValueError(
                f"Invalid unused byte: expected {cls.UNUSED_BYTE}, got {unused_byte}"
            )

        # Find matching msg_type
        msg_type = MsgType.from_value(msg_type_byte)

        # Extract message data; live_status handled for events only here
        remaining_data = message_layer[13:]
        msg_data = remaining_data
        live_status = b""

        if MsgType.is_event(msg_type):
            # Event messages have an internal variable-length structure before optional live status
            if len(remaining_data) < 8:
                raise ValueError("Event data too short for parsing")
            event_data_length = remaining_data[7]
            total_event_length = 8 + event_data_length
            if len(remaining_data) < total_event_length:
                raise ValueError(
                    f"Insufficient data for event: need {total_event_length}, got {len(remaining_data)}"
                )
            msg_data = remaining_data[:total_event_length]
            tail = remaining_data[total_event_length:]
            if len(tail) == cls.LIVE_STATUS_LENGTH:
                live_status = tail
            elif len(tail) != 0:
                raise ValueError(
                    f"Invalid live status length: expected {cls.LIVE_STATUS_LENGTH} or 0, got {len(tail)}"
                )
        # Note: GET_STATUS live_status is handled by device.parse_message/get_status logic

        # Build Message with decoded reference_id
        obj = cls(
            msg_type=msg_type,
            lock_address=lock_address,
            ref_id=ref_id,
            sequence_counter=sequence_counter,
            msg_data=msg_data,
            live_status=live_status,
            encrypted=user_enc == cls.ENCRYPTED,
            is_card_reader_response=False,
        )
        return obj

    def to_bytes(self) -> bytes:
        """
        Convert message to bytes.

        Returns:
        Complete message as bytes including total length and CRC
        """
        # Build application layer (device address + msg type + msg data)
        application_layer = struct.pack(">I B", self.lock_address, self.msg_byte)
        application_layer += self.msg_data

        # Build message layer (header + user_enc + unused + ref_id(byte) + sequence(uint32) + application layer)
        message_layer = struct.pack(
            ">B B B B I",
            self.HEADER_VERSION,
            self.ENCRYPTED if self.encrypted else self.UNENCRYPTED,
            self.UNUSED_BYTE,
            self.ref_id,
            self.sequence_counter,
        )
        message_layer += application_layer

        # Calculate message layer length (includes the length byte itself)
        message_layer_length = len(message_layer) + 1

        # Build message without total length byte (ACP + layer length + message layer)
        message_without_total_length = (
            struct.pack(">H B", self.ACP_IDENTIFIER, message_layer_length)
            + message_layer
        )

        # Add total length byte
        total_length = len(message_without_total_length) + 1 + 2
        message_with_total_length = (
            struct.pack(">B", total_length) + message_without_total_length
        )

        # Add CRC
        message_with_crc = self._add_crc16_ccitt(message_with_total_length)
        return message_with_crc

    def to_hex(self, separator: str = " ") -> str:
        """
        Convert message to hex string.

        Args:
            separator: Separator between hex bytes (default: space)

        Returns:
            Hex string representation
        """
        hex_bytes = self.to_bytes().hex().upper()
        if separator and len(separator) == 1:
            # Insert separator between each pair of hex characters
            return separator.join(
                hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)
            )
        else:
            # No separator or invalid separator
            return hex_bytes

    @staticmethod
    def _calculate_crc16_ccitt(data: bytes) -> int:
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

    @staticmethod
    def _add_crc16_ccitt(data: bytes) -> bytes:
        """Add CRC-16/CCITT checksum to data."""
        crc = Message._calculate_crc16_ccitt(data)
        return data + struct.pack(">H", crc)

    @property
    def info(self) -> dict:
        """Get message information as dictionary."""
        return {
            "command": self.msg_type.name,
            "command_value": f"0x{self.msg_type.value:02X}",
            "device_address": f"0x{self.lock_address:08X}",
            "sequence_counter": self.sequence_counter,
            "reference_id": self.ref_id,
            "msg_data_length": len(self.msg_data),
            "msg_data_hex": self.msg_data.hex(" ").upper() if self.msg_data else "",
            "live_status_hex": self.live_status.hex(" ").upper()
            if self.live_status
            else "",
            "encrypted": self.encrypted,
            "is_card_reader_response": self.is_card_reader_response,
            "total_length": len(self.to_bytes()),
        }

    def __repr__(self) -> str:
        """Detailed representation of the message."""
        return (
            f"Message(msg_type={self.msg_type.name}, device_address=0x{self.lock_address:08X}, "
            f"sequence_counter={self.sequence_counter}, reference_id={self.ref_id}, "
            f"msg_data={self.msg_data!r}, live_status={self.live_status!r}, "
            f"encrypted={self.encrypted}, is_card_reader_response={self.is_card_reader_response})"
        )

    def get_card_data(self) -> str:
        """
        Convenience method to get card data from READER_EVENT messages.

        This method automatically extracts the card data from the message data
        without requiring explicit extraction or validation steps.

        Returns:
            Card data as hex string in uppercase

        Raises:
            ValueError: If message is not a READER_EVENT type or data is invalid
        """
        if self.msg_type != MsgType.READER_EVENT:
            raise ValueError(
                f"Message is not READER_EVENT type, got {self.msg_type.name}"
            )

        data = self.msg_data
        if len(data) < 8:
            raise ValueError("READER_EVENT data too short (minimum 8 bytes required)")

        # Extract card data length (byte 7) and card data
        card_data_length = data[7]
        card_data = data[8 : 8 + card_data_length]

        if len(card_data) != card_data_length:
            raise ValueError(
                f"Card data length mismatch: expected {card_data_length}, got {len(card_data)}"
            )

        return card_data.hex().upper()


__all__ = ["MsgType", "Message"]


class ResponseCode(int, Enum):
    """Known response codes for MsgType.RESPONSE payloads."""

    SUCCESS = 0x00
    FAILURE = 0x0A
    SEQUENCE_MISMATCH = 0x07
    # Other codes can be added here as they are discovered


class Response:
    """
    Parser/helper for MsgType.RESPONSE payloads.

    Layout (minimal):
      - byte[0]: response code (e.g., 0x07 for sequence mismatch)
      - subsequent bytes: response data (code-specific payload)

    For SEQUENCE_MISMATCH (0x07):
      - data[0:4]: current sequence (big-endian uint32)
    """

    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data

    @classmethod
    def from_message(cls, msg: Message) -> Response:
        """Parse a Response from a Message."""
        if msg.msg_type != MsgType.RESPONSE:
            raise ValueError("Message is not of type RESPONSE")
        payload = msg.msg_data or b""
        if len(payload) < 1:
            raise ValueError("RESPONSE payload too short")
        code = payload[0]
        data = payload[1:]
        return cls(code=code, data=data)

    @property
    def success(self) -> bool:
        """Return True if the response indicates success."""
        return self.code == ResponseCode.SUCCESS

    @property
    def sequence_mismatch(self) -> bool:
        """Return True if the response indicates a sequence mismatch."""
        return self.code == ResponseCode.SEQUENCE_MISMATCH


# Ensure Response types are exported
__all__ = ["MsgType", "Message", "Response", "ResponseCode"]
