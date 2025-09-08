"""Pytest configuration and fixtures for testing gateway."""

import asyncio
import collections
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from src.py_simons_voss.gateway import GatewayNode

REF_ID = 42


@pytest_asyncio.fixture(name="responses")
async def yield_responses() -> AsyncGenerator[list[bytes | None], None]:
    """Yield a list to collect mock responses."""
    yield []


@pytest_asyncio.fixture
async def gateway(
    monkeypatch: pytest.MonkeyPatch, responses: list[bytes | None]
) -> AsyncGenerator[GatewayNode, None]:
    """
    Fixture that yields a gateway with its _reader and _writer mocked.
    In your test, set node._reader.read.side_effect = [resp1, resp2, ...]
    or node._reader.side_effect for full object mocking.
    """
    monkeypatch.setattr("random.randint", lambda a, b: REF_ID)
    response_iter = iter(responses)
    response_queue: collections.deque[bytes | None] = collections.deque([])

    def reader_read_side_effect(_: int) -> bytes:
        """Side effect for mock reader.read()."""
        if response_queue:
            if (response := response_queue.popleft()) is not None:
                if isinstance(response, Exception):
                    raise response
                return response
        raise asyncio.TimeoutError

    mock_reader = AsyncMock(spec=asyncio.StreamReader)
    mock_reader.read.side_effect = reader_read_side_effect

    def writer_write_side_effect(_: bytes) -> None:
        try:
            response_queue.append(next(response_iter))
        except StopIteration:
            pass

    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer.write.side_effect = writer_write_side_effect

    async def _open_connection(
        *args, **kwargs
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Return the mocked reader and writer."""
        return mock_reader, mock_writer

    monkeypatch.setattr(asyncio, "open_connection", _open_connection)
    node = GatewayNode(host="localhost", port=1234, address=100)
    monkeypatch.setattr(node, "get_status", AsyncMock(return_value=True))
    node._available = True
    node._reader = mock_reader
    node._writer = mock_writer
    node.event_callback = AsyncMock()
    yield node
    await node.disconnect()
