"""
Async TCP/IP Gateway Client with asyncio-based command queue and listener.

This module provides an AsyncGatewayNode that mirrors the behavior of the
threaded GatewayNode but uses asyncio streams and primitives. It manages:
 - connection and auto-reconnect
 - background listener task with message framing
 - a serialized command queue with retries and per-command response waiting
 - device routing and event callbacks
 - sequence mismatch handling and resend of last message
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
import logging
import random
from dataclasses import dataclass
from typing import Any, Callable, Union, cast

from .lock import Lock
from .exceptions import GatewayConnectionError, GatewayNotAvailable
from .helpers import normalize_address, mask_ref_id
from .message import Message, MsgType, ReferenceType, Response, ResponseCode

logger = logging.getLogger(__name__)


@dataclass
class MessageRequest:
    """Queued command with a prebuilt Message and awaitable state."""

    message: Message
    response_event: asyncio.Event
    response_message: Message | None = None


class GatewayNode:
    """Async TCP client with background listener and command processing."""

    def __init__(
        self,
        host: str,
        port: int,
        address: int | str,
        aes_passphrase: str | None = None,
        auto_reconnect: bool = True,
        event_callback: Callable[[Message], Coroutine[Any, Any, None] | None]
        | None = None,
    ) -> None:
        """Initialize gateway node state (async version)."""
        # Basic connection parameters
        self.host = host
        self.port = port
        self.address = normalize_address(address)
        self.aes_passphrase = aes_passphrase
        self.auto_reconnect = auto_reconnect
        self.event_callback = event_callback

        # Network stream handles
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected: bool = False
        self._available: bool = False

        # Concurrency primitives
        self._conn_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._queue_lock = asyncio.Lock()
        self._stop_event = asyncio.Event()

        # Background tasks & registry
        self._loop = asyncio.get_running_loop()
        self._tasks: set[asyncio.Future[Any]] = set()

        # Device registry
        self.locks: dict[int, Lock] = {}

        # Sequence counter & last sent message
        self.sequence_counter: int = 0
        self._sequence_lock = asyncio.Lock()
        self._last_message: Message | None = None

        # Command queue and in-flight tracking
        self._command_queue: asyncio.Queue[MessageRequest] = asyncio.Queue()
        self._current_request: MessageRequest | None = None

        # Timeouts / retry policy
        self.command_timeout_sec: float = 10.0
        self.timeout_retry_count: int = 2

    @property
    def available(self) -> bool:
        """Return True if the gateway is available for commands."""
        return self._available

    # --------- Connection management ---------
    async def connect(self) -> None:
        """Connect to the gateway and start background tasks."""
        async with self._conn_lock:
            if self._connected:
                logger.warning("Already connected to gateway")
                return

            attempt = 0
            delay = 2.0
            retries = 3
            while attempt <= retries:
                try:
                    logger.debug(
                        "Connecting to %s:%s (attempt %d/%d)...",
                        self.host,
                        self.port,
                        attempt + 1,
                        retries + 1,
                    )
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port), timeout=10.0
                    )
                    self._connected = True

                    # Clear stop flag and start tasks
                    self._stop_event.clear()
                    listener_task = self._loop.create_task(
                        self._listen_for_responses(), name="SocketListenerAsync"
                    )
                    self._tasks.add(listener_task)
                    listener_task.add_done_callback(self._tasks.remove)

                    processor_task = self._loop.create_task(
                        self._process_commands(), name="CommandProcessorAsync"
                    )
                    self._tasks.add(processor_task)
                    processor_task.add_done_callback(self._tasks.remove)

                    logger.info(
                        "✅ Connected to gateway at %s:%s (addr=0x%06X) — checking availability",
                        self.host,
                        self.port,
                        self.address,
                    )
                    # Probe availability synchronously; if it fails, raise
                    if not await self.get_status():
                        raise GatewayNotAvailable(
                            "Gateway did not respond to GET_STATUS during connect"
                        )
                    self._available = True
                    return

                except (asyncio.TimeoutError, OSError) as e:
                    await self._cleanup_connection()
                    attempt += 1
                    if attempt > retries:
                        if isinstance(e, asyncio.TimeoutError):
                            raise GatewayConnectionError(
                                f"Connection timeout to {self.host}:{self.port}"
                            ) from e
                        raise GatewayConnectionError(
                            f"Network error connecting to {self.host}:{self.port}: {e}"
                        ) from e
                    logger.warning(
                        "Connect attempt %d/%d failed: %s; retrying in %.1fs",
                        attempt,
                        retries + 1,
                        e,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    delay *= 1.5
                except Exception as e:  # pylint: disable=broad-except
                    await self._cleanup_connection()
                    raise GatewayConnectionError(
                        f"Unexpected error connecting to {self.host}:{self.port}: {e}"
                    ) from e

    async def disconnect(self) -> None:
        """Stop tasks and close the connection."""
        logger.debug("Disconnecting from gateway...")
        self._stop_event.set()
        await self._cleanup_connection()
        logger.debug("✅ Disconnected from gateway")

    # ========= Public command & device API =========
    async def send_and_wait(
        self,
        device_address: int,
        command: MsgType,
        msg_data: bytes = b"",
        is_card_reader_response: bool = False,
    ) -> Message | None:
        """Send a message to a device (or gateway) and wait for its answer.

        Returns the answering Message or None on timeout / failure.
        """
        if device_address != self.address and not self.available:
            logger.warning(
                "Gateway not available yet; rejecting command %s to %08X",
                command.name,
                device_address,
            )
            return None

        ref_id = random.randint(1, 63)
        message = Message(
            msg_type=command,
            device_address=device_address,
            ref_id=ref_id,
            sequence_counter=0,
            msg_data=msg_data,
            is_card_reader_response=is_card_reader_response,
        )
        request = MessageRequest(message=message, response_event=asyncio.Event())
        logger.debug(
            "📥 Queueing command %s for device %08X (ref_id=0x%02X)",
            command.name,
            device_address,
            request.message.ref_id,
        )
        await self._command_queue.put(request)
        await request.response_event.wait()
        if request.response_message:
            logger.debug("✅ Got response for ref_id=0x%02X", request.message.ref_id)
            return request.response_message
        logger.warning(
            "❌ No response received for ref_id=0x%02X within timeout",
            request.message.ref_id,
        )
        return None

    def add_lock(self, device_address: Union[int, str]) -> Lock:
        """Register a lock on this gateway and return it."""
        lock_address = normalize_address(device_address)
        device = Lock(self, lock_address)  # type: ignore[arg-type]
        self.locks[lock_address] = device
        return device

    def remove_lock(self, device_address: int) -> None:
        """Unregister a lock from this gateway."""
        self.locks.pop(device_address, None)

    def get_lock(self, device_address: int) -> Lock | None:
        """Return a registered lock or None."""
        return self.locks.get(device_address)

    async def get_status(self) -> bool:
        """Query the gateway's own status (GET_STATUS)."""
        reply = await self.send_and_wait(
            device_address=self.address,
            command=MsgType.GET_STATUS,
        )
        return reply is not None and reply.msg_type == MsgType.GET_STATUS

    # ========= Internal helpers (connection / lifecycle) =========
    async def _cleanup_connection(self) -> None:
        self._connected = False
        self._available = False

        # Cancel & await all registered tasks
        if self._tasks:
            _, pending = await asyncio.wait([*self._tasks], timeout=10)
            for task in pending:
                task.cancel()

        # Close writer
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # pylint: disable=broad-except
                pass
        self._writer = None
        self._reader = None

    async def _handle_reconnect(self) -> None:
        """Handle reconnection logic."""
        if self._stop_event.is_set() or not self.auto_reconnect:
            return
        logger.info("🔄 Attempting to reconnect to gateway...")
        await self._cleanup_connection()
        try:
            await self.connect()
        except (GatewayConnectionError, GatewayNotAvailable) as e:
            logger.error("❌ Failed to reconnect: %s", e)

    # --------- Listener and response routing ---------
    async def _listen_for_responses(self) -> None:
        """Continuously read framed messages and route them."""
        logger.debug("📡 Starting to listen for responses (async)...")
        buffer = bytearray()
        try:
            while not self._stop_event.is_set() and self._connected:
                if not self._reader:
                    await asyncio.sleep(0.1)
                    continue

                try:
                    chunk = await asyncio.wait_for(self._reader.read(1024), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:  # pylint: disable=broad-except
                    if self._stop_event.is_set():
                        break
                    logger.error("Socket error in listener: %s", e)
                    await self._handle_reconnect()
                    continue

                if not chunk:
                    # remote closed or no data; attempt reconnect
                    logger.warning("📡 Connection closed by gateway or empty read")
                    await self._handle_reconnect()
                    continue

                buffer.extend(chunk)
                # Frame extraction loop based on first length byte
                while True:
                    if len(buffer) < 1:
                        break
                    total_len = buffer[0]
                    if len(buffer) < total_len:
                        break  # wait for more
                    packet = bytes(buffer[:total_len])
                    del buffer[:total_len]
                    logger.debug(
                        "📨 Received %d bytes: %s", len(packet), packet.hex(" ").upper()
                    )
                    try:
                        self._handle_response(packet)
                    except Exception as e:  # pylint: disable=broad-except
                        logger.error("Error handling response: %s", e)
        finally:
            self._connected = False
            logger.debug("🔇 Async response listening stopped")

    def _handle_response(self, data: bytes) -> None:
        """Handle the received response message."""
        try:
            msg = Message.from_bytes(data)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Failed to decode message (%d bytes): %s", len(data), e)
            return

        if msg.ref_id_type == ReferenceType.CMD_EVENT:
            if not (lock := self.locks.get(msg.device_address)):
                logger.warning(
                    "Event for unregistered device %08X — ignored",
                    msg.device_address,
                )
                return
            # attach lock to message
            msg.lock = lock
            # update lock live status if present
            if msg.live_status:
                lock.update_status(msg.live_status)
            # async event callback (non-blocking)
            if self.event_callback is not None:
                try:
                    self._async_execute_callback(self.event_callback, msg)
                except Exception as e:  # pylint: disable=broad-except
                    logger.error("Failed to schedule event callback: %s", e)
            return

        # Early gate: for any non-event message, ensure it matches the current in-flight request
        if not self._current_request or (
            mask_ref_id(self._current_request.message.ref_id) != mask_ref_id(msg.ref_id)
            and self._current_request.message.msg_type != msg.msg_type
        ):
            logger.warning("Ignoring RESPONSE — no matching in-flight request")
            return

        if msg.msg_type == MsgType.RESPONSE:
            try:
                resp = Response.from_message(msg)
            except ValueError as e:
                logger.error("Error parsing RESPONSE: %s", e)
                return

            if resp.code == ResponseCode.SEQUENCE_MISMATCH:
                # sync and resend last message
                corrected_seq = resp.data + 1
                logger.debug(
                    "Sequence mismatch. Adjusting to %d and resending last command.",
                    corrected_seq,
                )
                self._loop.create_task(self._resend_last_message(corrected_seq))
                return

            if not resp.success:
                logger.debug(
                    "RESPONSE failed: code: %s, data: %s", resp.code, resp.data
                )

        # 3) ANSWER messages (via ref_id_type)
        # elif msg.ref_id_type == ReferenceType.ANSWER:
        #     # Gateway GET_STATUS answer: mark availability
        #     if (
        #         msg.device_address == self.address
        #         and msg.msg_type == MsgType.GET_STATUS
        #     ):
        #         self._available = True

        self._current_request.response_message = msg
        self._current_request.response_event.set()
        logger.debug(
            "📬 Delivered ANSWER to waiting command %s (ref=0x%02X)",
            self._current_request.message.msg_type.name,
            self._current_request.message.ref_id,
        )

    async def _send_bytes(self, message: bytes) -> None:
        # --------- Sending and command queue ---------
        """Send message to gateway."""
        async with self._send_lock:
            if not self._connected or not self._writer:
                raise GatewayConnectionError("Not connected to gateway")
            try:
                self._writer.write(message)
                await self._writer.drain()
                logger.debug(
                    "Sent command: %d bytes - %s",
                    len(message),
                    message.hex(" ").upper(),
                )
            except Exception as e:  # pylint: disable=broad-except
                logger.error("Send failed: %s", e)
                raise GatewayConnectionError(f"Failed to send command: {e}") from e

    async def _resend_last_message(self, new_sequence: int) -> None:
        """Resend the last message in case of error."""
        if not self._last_message:
            logger.warning("No last message to resend")
            return
        await self._update_sequence_counter(new_sequence)
        self._last_message.sequence_counter = new_sequence
        logger.debug(
            "Resending with ref_id=0x%02X, sequence=%d",
            self._last_message.ref_id,
            self._last_message.sequence_counter,
        )
        await self._send_bytes(self._last_message.to_bytes())

    async def _process_commands(self) -> None:
        logger.debug("🔄 Async command processor started")
        try:
            while not self._stop_event.is_set():
                try:
                    request = await asyncio.wait_for(
                        self._command_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                async with self._queue_lock:
                    self._current_request = request

                logger.debug(
                    "📤 Processing command %s for device %08X (ref_id=0x%02X)",
                    request.message.msg_type.name,
                    request.message.device_address,
                    request.message.ref_id,
                )

                max_attempts = 1 + int(self.timeout_retry_count)
                attempt = 0
                while attempt < max_attempts and not self._stop_event.is_set():
                    attempt += 1
                    try:
                        logger.debug(
                            "➡️  Attempt %d/%d for ref_id=0x%02X",
                            attempt,
                            max_attempts,
                            request.message.ref_id,
                        )
                        await self._send_message(request)
                    except GatewayConnectionError as e:
                        logger.warning(
                            "Send failed due to connection error for ref_id=0x%02X: %s — aborting command retries",
                            request.message.ref_id,
                            e,
                        )
                        request.response_message = None
                        request.response_event.set()
                        break

                    try:
                        await asyncio.wait_for(
                            request.response_event.wait(),
                            timeout=self.command_timeout_sec,
                        )
                    except asyncio.TimeoutError:
                        if attempt < max_attempts:
                            logger.warning(
                                "⏰ Command timeout (attempt %d/%d) for ref_id=0x%02X — retrying",
                                attempt,
                                max_attempts,
                                request.message.ref_id,
                            )
                            continue
                        logger.warning(
                            "⏰ Command timeout (final attempt %d/%d) for ref_id=0x%02X — giving up",
                            attempt,
                            max_attempts,
                            request.message.ref_id,
                        )
                        request.response_message = None
                        request.response_event.set()
                        break

                    # If event set, check message
                    if request.response_message is not None:
                        break

                async with self._queue_lock:
                    self._current_request = None
                self._command_queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:  # pylint: disable=broad-except
            logger.error("💥 Error in async command processor: %s", e)
        finally:
            logger.debug("🔄 Async command processor stopped")

    async def _send_message(self, request: MessageRequest) -> None:
        """Send message to gateway."""
        request.message.sequence_counter = await self._get_next_sequence()
        self._last_message = request.message
        await self._send_bytes(request.message.to_bytes())
        logger.debug("Built command %s", request.message.msg_type.name)

    def _async_execute_callback(
        self,
        callback: Callable[[Message], Coroutine[Any, Any, None] | None],
        *args: Any,
    ) -> None:
        """Run the async job in the executor."""
        task: asyncio.Future[None]
        if asyncio.iscoroutinefunction(callback):
            task = self._loop.create_task(callback(*args))
        else:
            task = self._loop.run_in_executor(
                None, cast(Callable[..., None], callback), *args
            )

        self._tasks.add(task)
        task.add_done_callback(self._tasks.remove)

    # --------- Sequence counter management ---------
    async def _get_next_sequence(self) -> int:
        """Get the next sequence number."""
        async with self._sequence_lock:
            self.sequence_counter += 1
            return self.sequence_counter

    async def _update_sequence_counter(self, new_sequence: int) -> None:
        """Update the sequence counter to a new value."""
        async with self._sequence_lock:
            self.sequence_counter = new_sequence
            logger.debug("Updated sequence counter to %d", new_sequence)
