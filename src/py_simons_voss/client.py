"""
Socket-based Gateway Client for Simons Voss communication with threaded listening.

This module provides a socket-based client class for communicating with a gateway
using TCP/IP protocol with optional AES encryption support and continuous background listening.
"""

import socket
import threading
import time
import logging
import queue
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Union, Optional
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from .message import Message, MsgType, Response
from .device import Lock


logger = logging.getLogger(__name__)


@dataclass
class CommandRequest:
    """Represents a command request waiting to be sent."""

    ref_id: int
    command: MsgType
    device_address: int
    msg_data: bytes
    is_card_reader_response: bool
    response_event: threading.Event
    response_message: Optional[Message] = None


class GatewayClientError(Exception):
    """Base exception for gateway client errors."""


class GatewayConnectionError(GatewayClientError):
    """Raised when connection to gateway fails."""


class AuthenticationError(GatewayClientError):
    """Raised when AES authentication fails."""


class ClientSocket:
    """
    Socket-based TCP IP client with threaded listening for continuous monitoring.

    Usage:
        client = ClientSocket(host, port, message_callback=on_message)
        client.connect()  # Connect in main thread (blocks until connected or fails)
        client.start_listening()  # Start background listener thread
        client.send_command(command)  # Send from main thread anytime
        client.stop()  # Stop listener and disconnect
    """

    def __init__(
        self,
        host: str,
        port: int,
        aes_passphrase: str | None = None,
        auto_reconnect: bool = True,
        event_callback: Callable[[Message], None] | None = None,
    ):
        """
        Initialize the socket gateway client.

        Args:
            host: Gateway IP address
            port: Gateway port number
            aes_passphrase: Optional AES passphrase for encryption
            auto_reconnect: Whether to automatically reconnect on connection loss
            message_callback: Optional callback to receive fully decoded Message objects
        """
        self.host = host
        self.port = port
        self.aes_passphrase = aes_passphrase
        self.auto_reconnect = auto_reconnect
        self.event_callback = event_callback

        self._socket: socket.socket | None = None
        self._connected = False
        self._listening = False
        self._stop_event = threading.Event()
        self._send_lock = threading.Lock()
        self._listener_thread: threading.Thread | None = None
        self.locks: dict[int, Lock] = {}

        # Sequence counter management (shared across all devices)
        self.sequence_counter = 0
        self._sequence_lock = threading.Lock()
        self._last_message: Message | None = None

        # Command queue management (to prevent concurrent sends)
        self._command_queue: queue.Queue[CommandRequest] = queue.Queue()
        self._command_processor_thread: Optional[threading.Thread] = None
        self._current_request: Optional[CommandRequest] = None
        self._queue_lock = threading.Lock()

        # Thread pool for executing event callbacks to prevent blocking the listener thread
        self._callback_executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="callback"
        )

    @property
    def is_connected(self) -> bool:
        """Check if client is connected to gateway."""
        return self._connected and self._socket is not None

    @property
    def is_encrypted(self) -> bool:
        """Check if communication is encrypted with AES."""
        return self.aes_passphrase is not None

    # def _init_aes_cipher(self) -> None:
    #     """Initialize AES cipher with the provided passphrase."""
    #     try:
    #         # Validate passphrase is available for AES operations
    #         if not self.aes_passphrase:
    #             raise AuthenticationError("AES passphrase is required")
    #         logger.debug("AES cipher initialized")
    #     except Exception as e:
    #         raise AuthenticationError(f"Failed to initialize AES cipher: {e}") from e

    def connect(self) -> None:
        """
        Connect to the gateway (runs in main thread).
        This method blocks until connected or raises an exception.
        """
        if self._connected:
            logger.warning("Already connected to gateway")
            return

        try:
            # Create socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(10.0)

            # Connect to gateway
            logger.debug("Connecting to %s:%s...", self.host, self.port)
            self._socket.connect((self.host, self.port))

            # Set timeout for listening operations
            self._socket.settimeout(1.0)

            self._connected = True
            logger.info("✅ Connected to gateway at %s:%s", self.host, self.port)

        except socket.timeout as exc:
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Connection timeout to {self.host}:{self.port}"
            ) from exc
        except socket.gaierror as exc:
            # DNS/hostname resolution error
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Could not resolve hostname {self.host}: {exc}"
            ) from exc
        except ConnectionRefusedError as exc:
            # Connection refused (port closed/service not running)
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Connection refused to {self.host}:{self.port} - service may not be running"
            ) from exc
        except OSError as exc:
            # Network unreachable, invalid port, etc.
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Network error connecting to {self.host}:{self.port}: {exc}"
            ) from exc
        except ValueError as exc:
            # Invalid IP address format or port number
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Invalid host/port format {self.host}:{self.port}: {exc}"
            ) from exc
        except Exception as e:
            # Catch any other unexpected errors
            self._cleanup_connection()
            raise GatewayConnectionError(
                f"Unexpected error connecting to {self.host}:{self.port}: {e}"
            ) from e
        self.start_listening()

    def start_listening(self) -> None:
        """
        Start the background listener thread.
        Must be called after connect().
        """
        if not self._connected:
            raise GatewayConnectionError("Must connect before starting listener")

        if self._listening:
            logger.warning("Listener thread is already running")
            return

        self._listening = True
        self._stop_event.clear()

        # Create and start the listener thread
        self._listener_thread = threading.Thread(
            target=self._listen_for_responses, name="SocketListener", daemon=True
        )
        self._listener_thread.start()

        # Create and start the command processor thread
        self._command_processor_thread = threading.Thread(
            target=self._process_commands, name="CommandProcessor", daemon=True
        )
        self._command_processor_thread.start()

        logger.info("🎧 Background listener and command processor threads started")

    def disconnect(self) -> None:
        """
        Stop listening and disconnect from the gateway.
        """
        logger.info("Disconnecting from gateway...")

        # Stop the listener thread
        if self._listening:
            self._stop_event.set()
            self._listening = False

            if self._listener_thread and self._listener_thread.is_alive():
                self._listener_thread.join(timeout=3.0)
                if self._listener_thread.is_alive():
                    logger.warning("Listener thread did not stop gracefully")

            # Stop the command processor thread
            if (
                self._command_processor_thread
                and self._command_processor_thread.is_alive()
            ):
                self._command_processor_thread.join(timeout=3.0)
                if self._command_processor_thread.is_alive():
                    logger.warning("Command processor thread did not stop gracefully")

        # Shutdown the callback thread pool
        self._callback_executor.shutdown(wait=True)

        # Close connection
        self._cleanup_connection()
        logger.info("✅ Disconnected from gateway")

    def _cleanup_connection(self) -> None:
        """Clean up connection resources."""
        self._connected = False

        # Close socket
        if self._socket:
            try:
                self._socket.close()
            except Exception:  # pylint: disable=broad-except
                pass
            self._socket = None

    def _listen_for_responses(self) -> None:
        """Listen for incoming responses from the gateway (runs in background thread)."""
        logger.debug("📡 Starting to listen for responses...")

        while not self._stop_event.is_set() and self._connected:
            try:
                # Check if we still have a valid connection
                if not self._socket:
                    break

                # Try to receive data
                try:
                    data = self._socket.recv(1024)
                except socket.timeout:
                    # Timeout is normal - just continue listening
                    continue
                except socket.error as e:
                    if self._stop_event.is_set():
                        break
                    logger.error("Socket error in listener: %s", e)
                    if self.auto_reconnect:
                        self._handle_reconnect()
                    break

                if not data:
                    # Connection closed by gateway
                    logger.warning("📡 Connection closed by gateway")
                    if self.auto_reconnect:
                        self._handle_reconnect()
                    break

                logger.debug(
                    "📨 Received %d bytes: %s", len(data), data.hex(" ").upper()
                )

                # Process the response
                try:
                    self._handle_response(data)
                except Exception as e:
                    logger.error("Error handling response: %s", e)

            except Exception as e:  # pylint: disable=broad-except
                if self._stop_event.is_set():
                    break
                logger.error("💥 Listener error: %s", e)
                break

        # Mark as disconnected when exiting listener
        self._connected = False
        logger.debug("🔇 Response listening stopped")

    def _handle_reconnect(self) -> None:
        """Handle automatic reconnection (runs in main thread loop)."""
        if self._stop_event.is_set():
            return

        logger.info("🔄 Attempting to reconnect to gateway...")

        # Clean up current connection
        self._connected = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

        max_retries = 5
        retry_delay = 2.0

        for attempt in range(max_retries):
            if self._stop_event.is_set():
                return

            try:
                time.sleep(retry_delay)

                # Create new socket
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(3.0)
                self._socket.connect((self.host, self.port))

                # Set timeout for listener
                self._socket.settimeout(10.0)
                self._connected = True
                logger.info("✅ Successfully reconnected to gateway")
                return

            except Exception as e:
                logger.warning("Reconnection attempt %d failed: %s", attempt + 1, e)
                retry_delay *= 1.5  # Exponential backoff

        logger.error("❌ Failed to reconnect after maximum attempts")

    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using AES encryption.

        Args:
            data: Raw data to encrypt

        Returns:
            Encrypted data with IV prepended
        """
        if not self.aes_passphrase:
            return data

        try:
            key = self.aes_passphrase.encode("utf-8")[:32].ljust(32, b"\0")
            iv = get_random_bytes(16)  # AES block size
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Pad data to multiple of 16 bytes
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Prepend IV to encrypted data
            return iv + encrypted_data

        except Exception as e:
            raise AuthenticationError(f"Failed to encrypt data: {e}") from e

    def _decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt AES encrypted data.

        Args:
            data: Encrypted data with IV prepended

        Returns:
            Decrypted raw data
        """
        if not self.aes_passphrase:
            return data

        try:
            key = self.aes_passphrase.encode("utf-8")[:32].ljust(32, b"\0")

            # Extract IV and encrypted data
            iv = data[:16]
            encrypted_data = data[16:]

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(encrypted_data)

            # Remove padding
            return unpad(decrypted_data, AES.block_size)

        except Exception as e:
            raise AuthenticationError(f"Failed to decrypt data: {e}") from e

    def send_command(self, command: bytes) -> None:
        """
        Send a command to the gateway.

        All responses are handled by the background listener thread via registered callback.

        Args:
            command: Command bytes to send

        Raises:
            GatewayConnectionError: If not connected or send fails
            AuthenticationError: If encryption fails
        """
        with self._send_lock:
            if not self._connected or not self._socket:
                raise GatewayConnectionError("Not connected to gateway")

            try:
                # Encrypt command if AES is enabled
                # encrypted_command = self._encrypt_data(command)

                # Send command
                self._socket.send(command)
                logger.debug(
                    "Sent command: %d bytes - %s",
                    len(command),
                    command.hex(" ").upper(),
                )

            except socket.error as e:
                logger.error("Send failed: %s", e)
                raise GatewayConnectionError(f"Failed to send command: {e}") from e
            except Exception as e:
                raise GatewayConnectionError(f"Failed to send command: {e}") from e

    def _handle_response(self, data: bytes) -> None:
        """
        Handle incoming response data (called from listener thread).

        Args:
            data: Raw response data from gateway
        """
        # Decrypt if AES is enabled
        decrypted_data = self._decrypt_data(data)

        # Decode and route a single complete message to registered devices
        try:
            msg = Message.from_bytes(decrypted_data)
        except Exception as e:
            logger.warning(
                "Failed to decode message (%d bytes): %s", len(decrypted_data), e
            )
            return

        # Handle sequence mismatch at client level before routing to device
        if msg.msg_type == MsgType.RESPONSE:
            try:
                resp = Response.from_message(msg)

                # Sequence mismatch handling at client level
                if resp.sequence_mismatch:
                    if len(resp.data) < 4:
                        logger.error(
                            "Received RESPONSE with sequence mismatch but invalid sequence data"
                        )
                        return
                    seq = int.from_bytes(resp.data[:4])
                    corrected_seq = seq + 1
                    logger.debug(
                        "Sequence mismatch. Adjusting to %d and resending last command.",
                        corrected_seq,
                    )
                    self.resend_last_message(corrected_seq)
                    return  # Don't route to device for sequence mismatch responses

            except Exception as e:
                logger.error("Error handling RESPONSE: %s", e)

        # Check if this response matches the current command request
        with self._queue_lock:
            current_request = self._current_request
            if (
                current_request
                and current_request.device_address == msg.lock_address
                and (current_request.ref_id & 0x3F) == (msg.ref_id & 0x3F)
            ):
                # This response is for the current command request
                # Note: We mask with 0x3F because the gateway sets upper bits in responses
                current_request.response_message = msg
                current_request.response_event.set()
                logger.debug(
                    "📬 Delivered response to waiting command (cmd_ref=0x%02X, resp_ref=0x%02X)",
                    current_request.ref_id,
                    msg.ref_id,
                )

        # Route to device for handling (state update and callback)
        if not (lock := self.locks.get(msg.lock_address)):
            logger.warning("No lock registered for address %08X", msg.lock_address)
            return
        try:
            msg.lock = lock
            lock.parse_message(msg)
        except Exception as e:
            logger.error("Device decode error for %08X: %s", msg.lock_address, e)

        logger.debug("Handled response: %d bytes", len(decrypted_data))

    def execute_callback_async(self, callback: Callable, *args) -> None:
        """Execute a callback function asynchronously in the thread pool."""
        try:
            self._callback_executor.submit(callback, *args)
        except Exception as e:
            logger.error("Error submitting callback: %s", e)

    # Sequence counter management
    def get_next_sequence(self) -> int:
        """Get the next sequence counter value (thread-safe)."""
        with self._sequence_lock:
            self.sequence_counter += 1
            return self.sequence_counter

    def update_sequence_counter(self, new_sequence: int) -> None:
        """Update the sequence counter to a specific value (thread-safe)."""
        with self._sequence_lock:
            self.sequence_counter = new_sequence
            logger.debug("Updated sequence counter to %d", new_sequence)

    def reset_sequence_counter(self, value: int = 0) -> None:
        """Reset the sequence counter to a specific value (thread-safe)."""
        with self._sequence_lock:
            self.sequence_counter = value
            logger.debug("Reset sequence counter to %d", value)

    def get_current_sequence(self) -> int:
        """Get the current sequence counter value (thread-safe)."""
        with self._sequence_lock:
            return self.sequence_counter

    def set_last_message(self, message: Message) -> None:
        """Store the last sent message for potential resending."""
        self._last_message = message

    def resend_last_message(self, new_sequence: int) -> None:
        """Resend the last sent message with an updated sequence counter."""
        if not self._last_message:
            logger.warning("No last message to resend")
            return

        # Update sequence counter in both the client and the stored message
        self.update_sequence_counter(new_sequence)
        self._last_message.sequence_counter = new_sequence

        # Re-encode and send the updated message
        logger.debug(
            "Resending with ref_id=0x%02X, sequence=%d",
            self._last_message.ref_id,
            self._last_message.sequence_counter,
        )
        self.send_command(self._last_message.to_bytes())

    # Command queue management
    def _process_commands(self) -> None:
        """Process commands from the queue one at a time (runs in background thread)."""
        logger.debug("🔄 Command processor started")

        while not self._stop_event.is_set():
            try:
                # Wait for a command request (with timeout to check stop event)
                try:
                    request = self._command_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Set current request for response routing
                with self._queue_lock:
                    self._current_request = request

                logger.debug(
                    "📤 Processing command %s for device %08X (ref_id=0x%02X)",
                    request.command.name,
                    request.device_address,
                    request.ref_id,
                )

                # Send the command
                self._send_command_internal(request)

                # Wait for response or timeout
                success = request.response_event.wait(timeout=5.0)  # 5 second timeout

                if not success:
                    logger.warning(
                        "⏰ Command timeout for ref_id=0x%02X", request.ref_id
                    )

                # Clear current request
                with self._queue_lock:
                    self._current_request = None

                # Mark task as done
                self._command_queue.task_done()

            except Exception as e:
                logger.error("💥 Error in command processor: %s", e)
                with self._queue_lock:
                    self._current_request = None

        logger.debug("🔄 Command processor stopped")

    def _send_command_internal(self, request: CommandRequest) -> None:
        """Send a single command request."""
        sequence_counter = self.get_next_sequence()

        # Create message instance
        message = Message(
            msg_type=request.command,
            lock_address=request.device_address,
            ref_id=request.ref_id,
            sequence_counter=sequence_counter,
            msg_data=request.msg_data,
            is_card_reader_response=request.is_card_reader_response,
        )

        # Store as last_message for potential resending
        self.set_last_message(message)

        # Convert to bytes and send
        command_bytes = message.to_bytes()
        self.send_command(command_bytes)
        logger.debug(
            "Built command %s: %s", request.command.name, command_bytes.hex(" ").upper()
        )

    def send_and_wait(
        self,
        device_address: int,
        command: MsgType,
        ref_id: int,
        msg_data: bytes = b"",
        is_card_reader_response: bool = False,
        timeout: float = 5.0,
    ) -> Optional[Message]:
        """
        Queue a command and wait for its response.
        This is the method that devices should call instead of sending directly.
        """
        # Create command request
        request = CommandRequest(
            ref_id=ref_id,
            command=command,
            device_address=device_address,
            msg_data=msg_data,
            is_card_reader_response=is_card_reader_response,
            response_event=threading.Event(),
        )

        # Add to queue
        logger.debug(
            "📥 Queueing command %s for device %08X (ref_id=0x%02X)",
            command.name,
            device_address,
            ref_id,
        )
        self._command_queue.put(request)

        # Wait for the command to be processed and response received
        success = request.response_event.wait(timeout=timeout + 1.0)  # Add buffer time

        if success and request.response_message:
            logger.debug("✅ Got response for ref_id=0x%02X", ref_id)
            return request.response_message
        else:
            logger.warning(
                "❌ No response received for ref_id=0x%02X within timeout", ref_id
            )
            return None

    # Device management
    def add_lock(self, lock_address: Union[int, str]) -> Lock:
        """
        Create and register a Lock device for the given address.

        Args:
            lock_address: Device address as int or hex string

        Returns:
            The created Lock device instance
        """
        # Handle string addresses
        if isinstance(lock_address, str):
            if lock_address.startswith("0x"):
                lock_address = int(lock_address, 16)
            else:
                lock_address = int(lock_address, 10)

        # Create the Lock device
        device = Lock(self, lock_address)

        # Add to devices dict
        self.locks[lock_address] = device

        return device

    def remove_lock(self, lock_address: int) -> None:
        """Unregister a lock by address."""
        self.locks.pop(lock_address, None)

    def get_lock(self, lock_address: int) -> Lock | None:
        """Retrieve a registered lock by address."""
        return self.locks.get(lock_address)
