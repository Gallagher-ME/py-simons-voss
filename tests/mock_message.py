"""Mocked Message for testing purposes."""

from re import S
import struct

from py_simons_voss.helpers import normalize_address
from py_simons_voss.message import MsgType
from src.py_simons_voss.helpers import calculate_crc


class MockMessage:
    """Mock message for testing purposes."""

    def __init__(
        self,
        *,
        device_address: int,
        ref_id: int,
        msg_data: str,
        msg_type: MsgType = MsgType.RESPONSE,
        sequence_counter: int = 0,
        live_status: bytes = b"",
        encrypted: bool = False,
        is_card_reader_response=False,
        header_version=0x01,
        acp_identifier=0xFEFD,
        crc: int | None = None,
    ):
        self.msg_type = msg_type
        self.device_address = normalize_address(device_address)
        self.ref_id = ref_id
        self.msg_data = bytes.fromhex(msg_data)
        self.sequence_counter = sequence_counter
        self.live_status = live_status
        self.encrypted = encrypted
        self.is_card_reader_response = is_card_reader_response
        self.header_version = header_version
        self.acp_identifier = acp_identifier
        self.crc = crc

    def to_bytes(self):
        """Convert the message to bytes."""
        application_layer = struct.pack(
            ">I B", self.device_address, self.msg_type.value
        )
        application_layer += self.msg_data

        message_layer = struct.pack(
            ">B B B B I",
            self.header_version,
            0x01 if self.encrypted else 0x00,
            0x00,
            self.ref_id,
            self.sequence_counter,
        )
        message_layer += application_layer

        message_layer_length = len(message_layer) + 1
        message_without_total_length = (
            struct.pack(">H B", self.acp_identifier, message_layer_length)
            + message_layer
        )

        total_length = len(message_without_total_length) + 1 + 2
        message_with_total_length = (
            struct.pack(">B", total_length) + message_without_total_length
        )
        if self.crc is None:
            self.crc = calculate_crc(message_with_total_length)
        return message_with_total_length + struct.pack(">H", self.crc)
