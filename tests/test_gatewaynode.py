"""Testing 123."""

import socket
import pytest

from py_simons_voss.lock import MsgType
from src.py_simons_voss.gateway import GatewayNode
from tests.mock_message import MockMessage

from .conftest import REF_ID, AsyncMock

DEVICE_1 = 200
DEVICE_2 = 300


@pytest.mark.asyncio
async def test_wrong_seq_counter(gateway: GatewayNode, responses: list[bytes]) -> None:
    """Test that the sequence counter is handled correctly."""
    response1 = MockMessage(
        device_address=512,
        ref_id=REF_ID,
        msg_data="0700000002",
        sequence_counter=0,
    ).to_bytes()
    response2 = MockMessage(
        msg_type=MsgType.GET_STATUS,
        device_address=512,
        ref_id=REF_ID,
        msg_data="8F000000000000",
        sequence_counter=3,
    ).to_bytes()
    responses.extend([response1, response2])
    await gateway.connect()
    assert gateway.sequence_counter == 0
    lock = gateway.add_lock(200)
    await lock.get_status()
    assert gateway.sequence_counter == 3


@pytest.mark.parametrize(
    "responses_to_add, expected_result, expected_calls",
    [
        ([], False, 3),
        (
            [
                None,  # First attempt will time out
                MockMessage(
                    msg_type=MsgType.GET_STATUS,
                    device_address=512,
                    ref_id=REF_ID,
                    msg_data="8F000000000000",
                    sequence_counter=1,
                ).to_bytes(),
            ],
            True,
            2,
        ),
    ],
)
@pytest.mark.asyncio
async def test_retrying_send_message(
    gateway: GatewayNode,
    responses: list[bytes | None],
    responses_to_add: list[bytes | None],
    expected_result: bool,
    expected_calls: int,
) -> None:
    """Test that sending a message retries on timeout."""
    responses.extend(responses_to_add)
    gateway.command_timeout_sec = 0.01
    await gateway.connect()
    lock = gateway.add_lock(200)
    result = await lock.get_status()
    assert result is expected_result
    assert gateway._writer.write.call_count == expected_calls


@pytest.mark.asyncio
async def test_handling_event_while_sending_command(
    gateway: GatewayNode, responses: list[bytes | None]
) -> None:
    """Test that sending a message retries on timeout."""
    responses.extend(
        [
            MockMessage(
                msg_type=MsgType.READER_EVENT,
                device_address=DEVICE_2,
                ref_id=0x00,
                msg_data="F3888500FF00000A0000000000002C26CA648F00400303",
                sequence_counter=1,
            ).to_bytes(),
            MockMessage(
                msg_type=MsgType.GET_STATUS,
                device_address=DEVICE_1,
                ref_id=(REF_ID & ~(0b11 << 6)) | (2 << 6),
                msg_data="8F000000000000",
                sequence_counter=2,
            ).to_bytes(),
        ]
    )
    mock_event_callback = AsyncMock()
    gateway.event_callback = mock_event_callback
    await gateway.connect()
    lock_1 = gateway.add_lock(DEVICE_1)
    lock_2 = gateway.add_lock(DEVICE_2)
    result = await lock_1.get_status()
    mock_event_callback.assert_called_once()
    assert lock_2.last_message is not None
    assert result


@pytest.mark.asyncio
async def test_receiving_invalid_message_crc(gateway: GatewayNode) -> None:
    """Test that sending a message retries on timeout."""
    gateway._reader.read.side_effect = [
        MockMessage(
            msg_type=MsgType.READER_EVENT,
            device_address=DEVICE_1,
            ref_id=0x00,
            msg_data="F3888500FF00000A0000000000002C26CA648F00400303",
            sequence_counter=1,
            crc=0x0000,  # Invalid CRC
        ).to_bytes()
    ]
    await gateway.connect()
    lock = gateway.add_lock(DEVICE_1)
    gateway.event_callback.assert_not_called()
    assert lock.last_message is None


@pytest.mark.asyncio
async def test_reconnecting_to_gateway(
    gateway: GatewayNode, responses: list[bytes | None]
) -> None:
    """Test that we try to reconnect if the connection is lost."""
    responses.extend(
        [
            MockMessage(
                msg_type=MsgType.GET_STATUS,
                device_address=DEVICE_1,
                ref_id=(REF_ID & ~(0b11 << 6)) | (2 << 6),
                msg_data="8F000000000000",
            ).to_bytes(),
        ]
    )
    await gateway.connect()
    lock = gateway.add_lock(DEVICE_1)
    gateway._connected = False  # Simulate lost connection
    result = await lock.get_status()
    assert result
    assert lock.last_message is None
