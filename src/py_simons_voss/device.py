"""
Simons Voss Device Command Builder

This module provides a comprehensive class for building and sending commands
to Simons Voss devices through a gateway. It handles command structure,
sequence counters, device addressing, and includes all available commands.
"""

from __future__ import annotations

import logging
import random
import struct
from enum import Enum
from typing import TYPE_CHECKING, Optional

from .message import Message, MsgType, ReferenceType, Response

if TYPE_CHECKING:  # avoid runtime import cycles
    from .client import ClientSocket

logger = logging.getLogger(__name__)


class BatteryStatus(Enum):
    """Battery status levels based on live status bits"""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    FULL = 3


class QosLevel(Enum):
    """Quality of Service levels based on live status bits"""

    BELOW_80 = 0
    MIN_80 = 1
    MIN_90 = 2
    MIN_95 = 3


class LockState(Enum):
    """Lock states based on live status bits"""

    LOCKED = 0
    UNLOCKED = 1


class Lock:
    """
    Command builder and manager for Simons Voss locks.

    This class handles the construction of command data structures including:
    - Device addressing
    - Sequence counter management
    - Reference byte with fixed value and protocol bits
    - CRC-16/CCITT checksum calculation
    - Command enumeration and execution

    Example:
        device = SimonsVossDevice(client, device_address=0x12345678, reference_fixed_value=10)
        command_data = device.get_status()
        # Send command_data through your socket connection
    """

    # Protocol constants for new message structure
    ACP_IDENTIFIER = 0xFEFD  # Fixed ACP Identifier
    HEADER_VERSION = 0x01  # Header version (always 0x01)
    UNENCRYPTED = 0x00  # Unencrypted flag
    ENCRYPTED = 0x01  # Encrypted flag
    UNUSED_BYTE = 0x00  # Unused byte (always 0x00)

    def __init__(self, client: ClientSocket, address: int):
        """
        Initialize the lock command builder.

        Args:
            client: The ClientSocket used to send commands and route messages
            address: The target device address (32-bit integer)
        """
        # Back-reference to a client for auto-sending commands and routing
        self._client = client
        self.address = address

        # Last received decoded message for this device (if any)
        self.last_message: Message | None = None
        self.last_command_successful = False

        # Live status derived fields (updated when live_status is received)
        self.battery_status = BatteryStatus.UNKNOWN
        self.qos_level: QosLevel | None = None
        self.lock_state: LockState | None = None
        self.lock_tampered = False

        logger.debug(
            "Initialized device %08X",
            address,
        )

        # Device will be registered with the client via client.add_lock() method
        self.response_timeout: float = 5.0

    # --- Command helpers ---
    def _gen_ref_id(self) -> int:
        """Generate a command ref_id (6-bit value with bits 6-7 = 00)."""
        return random.randint(1, 63)

    def _send_and_wait(
        self,
        command: MsgType,
        msg_data: bytes = b"",
        is_card_read_response: bool = False,
        timeout: Optional[float] = None,
    ) -> Optional[Message]:
        """
        Send a command and wait for response using the client's command queue.
        This ensures only one command is processed at a time across all devices.
        """
        rid = self._gen_ref_id()
        timeout = timeout if timeout is not None else self.response_timeout

        logger.debug("Sending command %s with ref_id=0x%02X", command.name, rid)

        # Use the client's send_and_wait method which handles queueing
        reply = self._client.send_and_wait(
            device_address=self.address,
            command=command,
            ref_id=rid,
            msg_data=msg_data,
            is_card_reader_response=is_card_read_response,
            timeout=timeout,
        )

        logger.debug(
            "Command completed for ref_id=0x%02X, got response: %s",
            rid,
            reply is not None,
        )
        return reply

    def parse_message(self, msg: Message) -> None:
        """
        Handle a received Message object:
        - Update live_status for event messages.
        - Forward CMD_EVENT messages to event_callback if set.

        Note: Response handling and sequence mismatch is now done at the client level.
        """
        # Store the received message for potential data extraction
        self.last_message = msg

        # Update live status if present (events carry live status here)
        if msg.live_status:
            self._update_from_live_status(msg.live_status)

        # Notify client's event callback for CMD_EVENT messages
        if (
            msg.ref_id_type == ReferenceType.CMD_EVENT
            and self._client.event_callback is not None
        ):
            # Execute callback asynchronously to prevent blocking the listener thread
            self._client.execute_callback_async(self._client.event_callback, msg)

    def get_status(self) -> bool:
        """Get device status. Wait for GET_STATUS reply and update live status from its data."""
        reply = self._send_and_wait(MsgType.GET_STATUS)
        if reply and reply.msg_type == MsgType.GET_STATUS and reply.msg_data:
            if len(reply.msg_data) >= 5:
                self._update_from_live_status(reply.msg_data[:5])
                return True
        return False

    # def get_system_info(self, timeout: Optional[float] = None) -> bytes:
    #     """Get system information and wait for response."""
    #     cmd_bytes, _ = self._send_and_wait(MsgType.GET_SYSTEM_INFO, timeout=timeout)
    #     return cmd_bytes

    def add_to_whitelist(
        self, user_id: Optional[int] = None, timeout: Optional[float] = None
    ) -> bool:
        """
        Add user to whitelist and wait for response.
        """
        msg_data = struct.pack(">I", user_id) if user_id is not None else b""
        if reply := self._send_and_wait(
            MsgType.ADD_TO_WHITELIST, msg_data, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def remove_from_whitelist(
        self, user_id: Optional[int] = None, timeout: Optional[float] = None
    ) -> bool:
        """
        Remove user from whitelist and wait for response.
        """
        msg_data = struct.pack(">I", user_id) if user_id is not None else b""
        if reply := self._send_and_wait(
            MsgType.REMOVE_FROM_WHITELIST, msg_data, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def delete_whole_whitelist(self, timeout: Optional[float] = None) -> bool:
        """Delete entire whitelist and wait for response."""
        if reply := self._send_and_wait(
            MsgType.DELETE_WHOLE_WHITELIST, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def deactivate_whitelist(self, timeout: Optional[float] = None) -> bool:
        """Deactivate whitelist and wait for response."""
        if reply := self._send_and_wait(MsgType.DEACTIVATE_WHITELIST, timeout=timeout):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def activate_whitelist(self, timeout: Optional[float] = None) -> bool:
        """Activate whitelist and wait for response."""
        if reply := self._send_and_wait(MsgType.ACTIVATE_WHITELIST, timeout=timeout):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def access_denied(self, timeout: Optional[float] = None) -> bool:
        """Send access denied and wait for response."""
        if reply := self._send_and_wait(
            MsgType.ACCESS_DENIED, is_card_read_response=True, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def short_term_activation(
        self,
        card_read_response=False,
        duration=0,
        timeout: Optional[float] = None,
    ) -> bool:
        """
        Activate device for short term and wait for response.
        """
        if duration != 0 and not 10 <= duration <= 250:
            raise ValueError("duration must be 0 or in range 10..250 (1/10 sec)")
        msg_data = struct.pack(">B", duration)
        if reply := self._send_and_wait(
            MsgType.SHORT_TERM_ACTIVATION, msg_data, card_read_response, timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def long_term_activation(
        self, duration_hours: Optional[int] = None, timeout: Optional[float] = None
    ) -> bool:
        """
        Activate device for long term and wait for response.
        """
        msg_data = (
            struct.pack(">I", duration_hours) if duration_hours is not None else b""
        )
        if reply := self._send_and_wait(
            MsgType.LONG_TERM_ACTIVATION, msg_data, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def long_term_release(self, timeout: Optional[float] = None) -> bool:
        """Release long term activation and wait for response."""
        if reply := self._send_and_wait(MsgType.LONG_TERM_RELEASE, timeout=timeout):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def office_mode_grant(self, timeout: Optional[float] = None) -> bool:
        """Grant office mode and wait for response."""
        if reply := self._send_and_wait(MsgType.OFFICE_MODE_GRANT, timeout=timeout):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def office_mode_release(self, timeout: Optional[float] = None) -> bool:
        """Release office mode and wait for response."""
        if reply := self._send_and_wait(MsgType.OFFICE_MODE_RELEASE, timeout=timeout):
            resp = Response.from_message(reply)
            return resp.success
        return False

    def delete_whole_priority_whitelist(self, timeout: Optional[float] = None) -> bool:
        """Delete entire priority whitelist and wait for response."""
        if reply := self._send_and_wait(
            MsgType.DELETE_WHOLE_PRIORITY_WHITELIST, timeout=timeout
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    @property
    def device_info(self) -> dict:
        """Get current device configuration."""
        info = {
            "device_address": f"{self.address:08X}",
        }
        if self.battery_status is not None:
            info["battery_status"] = self.battery_status.name
        if self.qos_level is not None:
            info["qos_level"] = self.qos_level.name
        return info

    def get_last_message(self) -> Message | None:
        """Return the last received message for this device, if any."""
        return self.last_message

    def clear_last_message(self) -> None:
        """Clear the stored last message."""
        self.last_message = None

    def get_last_card_data(self) -> str | None:
        """Return the card data (hex) from the last READER_EVENT, if available."""
        try:
            if self.last_message and self.last_message.msg_type == MsgType.READER_EVENT:
                return self.last_message.get_card_data()
        except ValueError:
            return None
        return None

    def _update_from_live_status(self, live_status: bytes) -> None:
        """Parse 5-byte live status and update battery_status and qos_level.

        We only use the lowest 4 bits of the first live_status byte:
          - bits 0-1: battery (0=UNKNOWN, 1=LOW, 3=OK)
          - bits 2-3: QoS (0=<80%, 1=≥80%, 2=≥90%, 3=≥95%)
        """
        if not live_status or len(live_status) < 1:
            return

        b0 = live_status[0]
        batt_bits = b0 & 0b11
        qos_bits = (b0 >> 2) & 0b11

        # Map battery bits directly to BatteryStatus Enum
        try:
            self.battery_status = BatteryStatus(batt_bits)
        except ValueError:
            self.battery_status = BatteryStatus.UNKNOWN

        # Map QoS bits
        try:
            self.qos_level = QosLevel(qos_bits)
        except ValueError:
            self.qos_level = None

        # if bit 7 of the first byte is 1 we can update the device lock state from the third byte
        if b0 & 0b10000000:
            # lock state is bit 2
            lock_bit = (live_status[2] & 0b100) >> 2
            try:
                self.lock_state = LockState(lock_bit)
            except ValueError:
                self.lock_state = None
            # lock housing cover is bit 7
            cover_bit = (live_status[2] & 0b10000000) >> 7
            self.lock_tampered = bool(cover_bit)
