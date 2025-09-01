#!/usr/bin/env python3
r"""
Async: Wait for a card read event from the Simons Voss gateway.

Defaults:
  - host: 192.168.55.117
  - port: 2101
  - device address: 0x00000200

Usage (Windows cmd.exe):
    python tests\wait_for_card_event.py
    # Or override
    python tests\wait_for_card_event.py --host 192.168.55.117 --port 2101 --device-address 0x00000200 --timeout 60
"""

import argparse
import asyncio
import logging

from py_simons_voss import GatewayNode, GatewayClientError, Message
from py_simons_voss.message import MsgType


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Wait for Simons Voss card read event (async)"
    )
    p.add_argument("--host", default="192.168.55.117", help="Gateway IP address")
    p.add_argument("--port", default=2101, type=int, help="Gateway TCP port")
    p.add_argument(
        "--device-address",
        default="0x00000200",
        help="Device address as hex (e.g., 0x00000200) or decimal",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Seconds to wait before exiting; <=0 waits indefinitely (default: 0)",
    )
    return p


async def main_async() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # Parse device address flexibly (accepts 0x.. or decimal)
    addr_str = args.device_address.strip()

    # Async event callback; it's safe to enqueue commands from here
    async def on_message(msg: Message) -> None:
        try:
            info = msg.info
            print("\nIncoming message:")
            print(f"  Command: {info['command']} ({info['command_value']})")
            print(f"  Device:  {info['device_address']}")
            print(f"  Seq:     {info['sequence_counter']}")
            if info["msg_data_hex"]:
                print(f"  Data:    {info['msg_data_hex']}")
            if info["live_status_hex"]:
                print(f"  Status:  {info['live_status_hex']}")
        except (KeyError, AttributeError, ValueError):
            pass

        # Only handle card read events (READER_EVENT)
        if getattr(msg, "msg_type", None) == MsgType.READER_EVENT:
            try:
                card_hex = msg.get_card_data()
                print("\nREADER_EVENT:")
                print(f"  Card length: {len(card_hex) // 2} bytes")
                print(f"  Card data:   {card_hex}")
                if card_hex == "00000004366FB2BB6380":
                    result = await msg.lock.activate_shortly(0, True)
                else:
                    result = await msg.lock.access_denied()
                print(f"  Activation result: {result}")
            except ValueError as e:
                print(f"Failed to handle READER_EVENT: {e}")

    client = GatewayNode(
        host=args.host,
        port=args.port,
        address=100,
        auto_reconnect=True,
        event_callback=on_message,
    )

    # Create locks
    device1 = client.add_lock(addr_str)
    print(f"Lock created: {device1.device_info}")
    device2 = client.add_lock("300")
    print(f"Lock created: {device2.device_info}")

    try:
        print(f"Connecting to gateway {args.host}:{args.port}...")
        await client.connect()
        print("Connected. Probing availability and listening for messages...")
        await device1.get_status()
        print("Listening for events continuously. Press Ctrl+C to quit.")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass

        return 0

    except GatewayClientError as e:
        print(f"Connection error: {e}")
        return 3
    finally:
        await client.disconnect()


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    raise SystemExit(main())
