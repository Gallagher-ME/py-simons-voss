"""
Simons Voss Device Command Builder

This module provides a comprehensive class for building and sending commands
to Simons Voss devices through a gateway. It handles command structure,
sequence counters, device addressing, and includes all available commands.
"""

from __future__ import annotations

import logging
import struct
from enum import Enum
from typing import TYPE_CHECKING, Any

from .message import Message, MsgType, Response, ResponseCode

if TYPE_CHECKING:
    from .gateway import GatewayNode

logger = logging.getLogger(__name__)


class BatteryStatus(Enum):
    """Battery status levels based on live status bits"""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    FULL = 3

    def __str__(self) -> str:
        mapping = {
            BatteryStatus.UNKNOWN: "unknown",
            BatteryStatus.LOW: "low",
            BatteryStatus.MEDIUM: "medium",
            BatteryStatus.FULL: "full",
        }
        return mapping[self]


class QosLevel(Enum):
    """Quality of Service levels based on live status bits"""

    BELOW_80 = 0
    MIN_80 = 1
    MIN_90 = 2
    MIN_95 = 3


class LockState(Enum):
    """Lock states based on live status bits"""

    NOT_ENGAGED = 0
    ENGAGED = 1


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

    def __init__(self, client: GatewayNode, address: int, name: str = "") -> None:
        """
        Initialize the lock command builder.

        Args:
            client: The GatewayNode used to send commands and route messages
            address: The target device address (32-bit integer)
        """
        # Back-reference to a client for auto-sending commands and routing
        self._client = client
        self.address = address
        self._name = name

        # Last received decoded message for this device (if any)
        self.last_message: Message | None = None

        # Live status derived fields (updated when live_status is received)
        self.battery_status = BatteryStatus.UNKNOWN
        self.qos_level: QosLevel | None = None
        self.lock_state: LockState | None = None
        self.lock_tampered = False

        logger.debug("Initialized device %08X", address)

    @property
    def name(self) -> str:
        """Return the device name."""
        return self._name

    async def _send_and_wait(
        self,
        command: MsgType,
        msg_data: bytes = b"",
        is_card_read_response: bool = False,
    ) -> Message | None:
        """Async: queue a command and await its response via the client's queue."""
        logger.debug("Sending command %s", command.name)
        reply = await self._client.send_and_wait(
            device_address=self.address,
            command=command,
            msg_data=msg_data,
            is_card_reader_response=is_card_read_response,
        )
        logger.debug("Command completed, got response: %s", reply is not None)
        return reply

    async def get_status(self) -> bool:
        """Async: Get device status and update live status from the reply."""
        reply = await self._send_and_wait(MsgType.GET_STATUS)
        if reply and reply.msg_type == MsgType.GET_STATUS and reply.msg_data:
            if len(reply.msg_data) >= 5:
                self.update_status(reply.msg_data[:5])
                return True
        return False

    # def get_system_info(self,) -> bytes:
    #     """Get system information and wait for response."""
    #     cmd_bytes, _ = self._send_and_wait(MsgType.GET_SYSTEM_INFO, timeout=timeout)
    #     return cmd_bytes

    async def add_to_whitelist(self, user_id: int | None = None) -> bool:
        """
        Async: Add user to whitelist and wait for response.
        """
        msg_data = struct.pack(">I", user_id) if user_id is not None else b""
        if reply := await self._send_and_wait(MsgType.ADD_TO_WHITELIST, msg_data):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def remove_from_whitelist(self, user_id: int | None = None) -> bool:
        """
        Async: Remove user from whitelist and wait for response.
        """
        msg_data = struct.pack(">I", user_id) if user_id is not None else b""
        if reply := await self._send_and_wait(MsgType.REMOVE_FROM_WHITELIST, msg_data):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def delete_whole_whitelist(self) -> bool:
        """Async: Delete entire whitelist and wait for response."""
        if reply := await self._send_and_wait(MsgType.DELETE_WHOLE_WHITELIST):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def deactivate_whitelist(self) -> bool:
        """Async: Deactivate whitelist and wait for response."""
        if reply := await self._send_and_wait(MsgType.DEACTIVATE_WHITELIST):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def activate_whitelist(self) -> bool:
        """Async: Activate whitelist and wait for response."""
        if reply := await self._send_and_wait(MsgType.ACTIVATE_WHITELIST):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def access_denied(self) -> bool:
        """Async: Send access denied and wait for response."""
        if reply := await self._send_and_wait(
            MsgType.ACCESS_DENIED, is_card_read_response=True
        ):
            resp = Response.from_message(reply)
            if resp.code is ResponseCode.UNEXPECTED:
                logger.warning("Access denied message was not expected by the lock.")
            return resp.success
        return False

    async def activate_shortly(self, duration=0, card_read_response=False) -> bool:
        """Async: Activate device for short term and wait for response."""
        if self.lock_state == LockState.ENGAGED:
            logger.warning("Lock is already engaged, cannot short term activate")
            return False
        if duration != 0 and not 10 <= duration <= 250:
            raise ValueError("duration must be 0 or in range 10..250 (1/10 sec)")
        msg_data = struct.pack(">B", duration)
        if reply := await self._send_and_wait(
            MsgType.SHORT_TERM_ACTIVATION, msg_data, card_read_response
        ):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def activate_long(
        self, delay: int = 0, duration: int = 0, card_read_response=False
    ) -> bool:
        """Async: Activate device for long term and wait for response."""
        if delay > 1440:
            raise ValueError("delay must be in range 0..1440 (minutes)")
        if duration > 1440:
            raise ValueError("duration must be in range 0..1440 (minutes)")
        msg_data = struct.pack("<HH", delay, duration)
        if reply := await self._send_and_wait(
            MsgType.LONG_TERM_ACTIVATION, msg_data, card_read_response
        ):
            resp = Response.from_message(reply)
            if resp.code is ResponseCode.UNEXPECTED:
                logger.warning(
                    "Long term activation failed, lock is already activated or a card read response was expected."
                )
            return resp.success
        return False

    async def long_term_release(self, delay: int = 0) -> bool:
        """Async: Release long term activation and wait for response."""
        msg_data = struct.pack(">H", delay)
        if reply := await self._send_and_wait(MsgType.LONG_TERM_RELEASE, msg_data):
            resp = Response.from_message(reply)
            if resp.code is ResponseCode.UNEXPECTED:
                logger.warning("Long term release failed, lock is already released")
            return resp.success
        return False

    async def office_mode_grant(self) -> bool:
        """Async: Grant office mode and wait for response."""
        if reply := await self._send_and_wait(MsgType.OFFICE_MODE_GRANT):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def office_mode_release(self) -> bool:
        """Async: Release office mode and wait for response."""
        if reply := await self._send_and_wait(MsgType.OFFICE_MODE_RELEASE):
            resp = Response.from_message(reply)
            return resp.success
        return False

    async def delete_whole_priority_whitelist(
        self,
    ) -> bool:
        """Async: Delete entire priority whitelist and wait for response."""
        if reply := await self._send_and_wait(MsgType.DELETE_WHOLE_PRIORITY_WHITELIST):
            resp = Response.from_message(reply)
            return resp.success
        return False

    @property
    def device_info(self) -> dict:
        """Get current device configuration."""
        info: dict[str, Any] = {"device_address": f"{self.address:08X}"}
        if self.battery_status is not None:
            info["battery_status"] = self.battery_status.name
        if self.qos_level is not None:
            info["qos_level"] = self.qos_level.name
        if self.lock_state is not None:
            info["lock_state"] = self.lock_state.name
        info["lock_tampered"] = self.lock_tampered
        return info

    def get_last_card_data(self) -> str | None:
        """Return the card data (hex) from the last READER_EVENT, if available."""
        try:
            if self.last_message and self.last_message.msg_type == MsgType.READER_EVENT:
                return self.last_message.get_card_data()
        except ValueError:
            return None
        return None

    def update_status(self, live_status: bytes) -> None:
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
