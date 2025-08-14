#!/usr/bin/env python3
"""
Wait for a card read event from the Simons Voss gateway.

Defaults:
  - host: 192.168.55.117
  - port: 2101
  - device address: 0x00000200

Usage (Windows cmd.exe):
  python wait_for_card_event.py
  # Or override
  python wait_for_card_event.py --host 192.168.55.117 --port 2101 --device-address 0x00000200 --timeout 60
"""

import argparse
import logging
import time

from py_simons_voss.client import ClientSocket, GatewayConnectionError
from py_simons_voss.message import Message, MsgType


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Wait for Simons Voss card read event")
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


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # Parse device address flexibly (accepts 0x.. or decimal)
    addr_str = args.device_address.strip()
    try:
        device_addr = int(addr_str, 0)
    except ValueError:
        print(f"Invalid device address: {addr_str}")
        return 2

    def on_message(msg: Message) -> None:
        # Print basic message info
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
        except Exception:
            pass

        # Only handle card read events (READER_EVENT)
        if getattr(msg, "msg_type", None) == MsgType.READER_EVENT:
            try:
                card_hex = msg.get_card_data()
                print("\nREADER_EVENT:")
                print(f"  Card length: {len(card_hex) // 2} bytes")
                print(f"  Card data:   {card_hex}")
                if card_hex == "00000004366FB2BB6380":
                    result = msg.lock.short_term_activation(True)
                else:
                    result = msg.lock.access_denied()
                print(f"  Activation result: {result}")
            except Exception as e:
                print(f"Failed to extract READER_EVENT data: {e}")

    client = ClientSocket(
        host=args.host,
        port=args.port,
        auto_reconnect=True,
        event_callback=on_message,
    )

    # Create lock with mandatory client
    device1 = client.add_lock(device_addr)
    print(f"Lock created: {device1.device_info}")
    device2 = client.add_lock(0x00000300)
    print(f"Lock created: {device2.device_info}")

    try:
        print(f"Connecting to gateway {args.host}:{args.port}...")
        client.connect()
        print("Connected. Listening for messages...")
        device1.get_status()

        # Keep listening in a loop until keyboard interrupt
        print("Listening for events continuously. Press Ctrl+C to quit.")
        while True:
            time.sleep(1)  # Small sleep to prevent busy waiting

    except GatewayConnectionError as e:
        print(f"Connection error: {e}")
        return 3
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        return 130
    finally:
        client.disconnect()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    raise SystemExit(main())
