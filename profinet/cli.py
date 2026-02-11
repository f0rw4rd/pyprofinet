"""
PROFINET command-line interface.

Provides CLI commands for device discovery and interaction.

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from typing import Optional

from . import dcp, rpc
from .dcp import (
    RESET_MODE_ALL_DATA,
    RESET_MODE_APPLICATION,
    RESET_MODE_COMMUNICATION,
    RESET_MODE_DEVICE,
    RESET_MODE_ENGINEERING,
    RESET_MODE_FACTORY,
)
from .exceptions import (
    DCPDeviceNotFoundError,
    PermissionDeniedError,
    ProfinetError,
    RPCError,
)
from .protocol import PNInM0, PNInM1, PNInM2, PNInM3
from .util import ethernet_socket, get_mac

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging based on verbosity flags."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def cmd_discover(args: argparse.Namespace) -> int:
    """Execute discover command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Discovering PROFINET devices on {args.interface}...")
        dcp.send_discover(sock, src)
        responses = dcp.read_response(sock, src, timeout_sec=args.timeout, debug=args.verbose)

        if not responses:
            print("No devices found")
            return 0

        print(f"\nFound {len(responses)} device(s):\n")
        for mac, blocks in responses.items():
            desc = dcp.DCPDeviceDescription(mac, blocks)
            print(f"  {desc.name}")
            print(f"    MAC:    {desc.mac}")
            print(f"    IP:     {desc.ip}")
            print(f"    Vendor: {desc.vendor_name} (0x{desc.vendor_id:04X})")
            print(f"    Device: 0x{desc.device_id:04X}")
            print()

        return 0
    finally:
        sock.close()


def cmd_get_param(args: argparse.Namespace) -> int:
    """Execute get-param command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        result = dcp.get_param(sock, src, args.target, args.param)
        if result:
            if args.param == "name":
                print(result.decode("utf-8", errors="replace"))
            elif args.param == "ip":
                from .util import s2ip

                print(s2ip(result[:4]))
            else:
                print(result.hex())
        else:
            print(f"Could not read parameter '{args.param}'")
            return 1

        return 0
    finally:
        sock.close()


def cmd_set_param(args: argparse.Namespace) -> int:
    """Execute set-param command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        success = dcp.set_param(sock, src, args.target, args.param, args.value)
        if success:
            print(f"Set {args.param} = {args.value}")
            return 0
        else:
            print(f"Failed to set {args.param}")
            return 1
    finally:
        sock.close()


def cmd_read(args: argparse.Namespace) -> int:
    """Execute read command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)

            idx = int(args.index, 16) if args.index.startswith("0x") else int(args.index)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=idx)

            print(f"Read {len(iod.payload)} bytes:")
            print(iod.payload.hex())

        return 0
    finally:
        sock.close()


def cmd_read_inm0_filter(args: argparse.Namespace) -> int:
    """Execute read-inm0-filter command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            data = conn.read_inm0filter()

            print("\nDevice Topology:")
            for api in data.keys():
                print(f"\nAPI {api}:")
                for slot_number, (module_id, subslots) in data[api].items():
                    print(f"  Slot {slot_number}: Module 0x{module_id:04X}")
                    for subslot_number, submodule_id in subslots.items():
                        print(f"    Subslot {subslot_number}: Submodule 0x{submodule_id:04X}")

        return 0
    finally:
        sock.close()


def cmd_read_inm0(args: argparse.Namespace) -> int:
    """Execute read-inm0 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM0.IDX)

            if iod.payload:
                im0 = PNInM0(iod.payload)
                print(im0)
            else:
                print("No IM0 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm1(args: argparse.Namespace) -> int:
    """Execute read-inm1 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM1.IDX)

            if iod.payload:
                im1 = PNInM1(iod.payload)
                print(im1)
            else:
                print("No IM1 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm2(args: argparse.Namespace) -> int:
    """Execute read-inm2 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM2.IDX)

            if iod.payload:
                im2 = PNInM2(iod.payload)
                print(im2)
            else:
                print("No IM2 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm3(args: argparse.Namespace) -> int:
    """Execute read-inm3 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM3.IDX)

            if iod.payload:
                im3 = PNInM3(iod.payload)
                print(im3)
            else:
                print("No IM3 data available")

        return 0
    finally:
        sock.close()


def cmd_set_ip(args: argparse.Namespace) -> int:
    """Execute set-ip command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Setting IP {args.ip} on {args.target}...")
        success = dcp.set_ip(
            sock,
            src,
            args.target,
            args.ip,
            args.netmask,
            args.gateway,
            permanent=args.permanent,
        )
        if success:
            print(f"Set IP={args.ip} netmask={args.netmask} gateway={args.gateway}")
            return 0
        else:
            print("Failed to set IP (timeout)")
            return 1
    finally:
        sock.close()


def cmd_signal(args: argparse.Namespace) -> int:
    """Execute signal command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Signalling device {args.target}...")
        success = dcp.signal_device(sock, src, args.target)
        if success:
            print("Device LED flash triggered")
            return 0
        else:
            print("Failed to signal device (timeout)")
            return 1
    finally:
        sock.close()


RESET_MODES = {
    "communication": RESET_MODE_COMMUNICATION,
    "application": RESET_MODE_APPLICATION,
    "engineering": RESET_MODE_ENGINEERING,
    "all-data": RESET_MODE_ALL_DATA,
    "device": RESET_MODE_DEVICE,
    "factory": RESET_MODE_FACTORY,
}


def cmd_reset(args: argparse.Namespace) -> int:
    """Execute reset command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)
        mode = RESET_MODES[args.mode]

        print(f"Resetting device {args.target} (mode: {args.mode})...")
        success = dcp.reset_to_factory(sock, src, args.target, mode=mode)
        if success:
            print("Reset command acknowledged")
            return 0
        else:
            print("Failed to reset device (timeout)")
            return 1
    finally:
        sock.close()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="profinet",
        description="PROFINET IO-Controller CLI",
        epilog="Credits: Original implementation by Alfred Krohmer (2015)",
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        metavar="IFACE",
        help="Network interface to use",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Discovery timeout in seconds (default: 10)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # discover
    sub = subparsers.add_parser("discover", help="Discover PROFINET devices")
    sub.set_defaults(func=cmd_discover)

    # get-param
    sub = subparsers.add_parser("get-param", help="Read device parameter")
    sub.add_argument("target", help="Target MAC address")
    sub.add_argument("param", choices=["name", "ip"], help="Parameter to read")
    sub.set_defaults(func=cmd_get_param)

    # set-param
    sub = subparsers.add_parser("set-param", help="Write device parameter")
    sub.add_argument("target", help="Target MAC address")
    sub.add_argument("param", choices=["name", "ip"], help="Parameter to write")
    sub.add_argument("value", help="New value")
    sub.set_defaults(func=cmd_set_param)

    # read
    sub = subparsers.add_parser("read", help="Read data record")
    sub.add_argument("target", help="Target station name")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, required=True, help="Slot number")
    sub.add_argument("--subslot", type=int, required=True, help="Subslot number")
    sub.add_argument("--index", required=True, help="Record index (hex with 0x prefix)")
    sub.set_defaults(func=cmd_read)

    # read-inm0-filter
    sub = subparsers.add_parser("read-inm0-filter", help="Read device topology")
    sub.add_argument("target", help="Target station name")
    sub.set_defaults(func=cmd_read_inm0_filter)

    # read-inm0
    sub = subparsers.add_parser("read-inm0", help="Read IM0 identification data")
    sub.add_argument("target", help="Target station name")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm0)

    # read-inm1
    sub = subparsers.add_parser("read-inm1", help="Read IM1 tag data")
    sub.add_argument("target", help="Target station name")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm1)

    # read-inm2
    sub = subparsers.add_parser("read-inm2", help="Read IM2 date data")
    sub.add_argument("target", help="Target station name")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm2)

    # read-inm3
    sub = subparsers.add_parser("read-inm3", help="Read IM3 descriptor data")
    sub.add_argument("target", help="Target station name")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm3)

    # set-ip
    sub = subparsers.add_parser("set-ip", help="Set device IP configuration via DCP")
    sub.add_argument("target", help="Target MAC address")
    sub.add_argument("ip", help="IP address")
    sub.add_argument("netmask", help="Subnet mask")
    sub.add_argument("gateway", help="Gateway address")
    sub.add_argument("--permanent", action="store_true", help="Save IP permanently")
    sub.set_defaults(func=cmd_set_ip)

    # signal
    sub = subparsers.add_parser("signal", help="Flash device LEDs")
    sub.add_argument("target", help="Target MAC address")
    sub.set_defaults(func=cmd_signal)

    # reset
    sub = subparsers.add_parser("reset", help="Reset device to factory settings")
    sub.add_argument("target", help="Target MAC address")
    sub.add_argument(
        "--mode",
        choices=["communication", "application", "engineering", "all-data", "device", "factory"],
        default="factory",
        help="Reset mode (default: factory)",
    )
    sub.set_defaults(func=cmd_reset)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose, args.debug)

    try:
        return args.func(args)
    except PermissionDeniedError:
        print("Error: Root privileges required for raw socket access", file=sys.stderr)
        return 1
    except DCPDeviceNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except RPCError as e:
        print(f"RPC Error: {e}", file=sys.stderr)
        return 1
    except ProfinetError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 130
    except Exception as e:
        logger.exception("Unexpected error")
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
