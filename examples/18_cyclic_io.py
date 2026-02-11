#!/usr/bin/env python3
"""
Cyclic IO Demo (RT_CLASS_1).

Demonstrates PROFINET cyclic data exchange using RT_CLASS_1.

This example:
1. Discovers the device via DCP
2. Connects with IOCR blocks for cyclic IO
3. Sends parameter phase (PrmBegin/PrmEnd)
4. Signals ApplicationReady
5. Starts cyclic data exchange

Requires root privileges for raw socket access.
Run with: sudo python3 18_cyclic_io.py

Press Ctrl+C to stop.
"""

import os
import signal
import sys
import time

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profinet import (
    IOCRSetup,
    IOSlot,
    RPCCon,
    ethernet_socket,
    get_mac,
    read_response,
    send_discover,
)
from profinet.cyclic import CyclicController
from profinet.rt import (
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOCRConfig,
    IODataObject,
)

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "")

# Cycle time in ms
# WARNING: Python has timing limitations due to the GIL and OS scheduling!
# - 32ms (default): Safe, reliable on all systems
# - 16ms: Usually works, may have minor jitter
# - 8ms:  Minimum practical, expect some jitter under load
# - <8ms: NOT RECOMMENDED - will have timing issues
# - <1ms: IMPOSSIBLE in Python
CYCLE_TIME_MS = int(os.environ.get("PROFINET_CYCLE_MS", "32"))

# Flag for clean shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C."""
    global running
    print("\nShutting down...")
    running = False


def discover_device(interface: str, device_name: str) -> dict:
    """Discover device via DCP."""
    print(f"Discovering '{device_name}' on {interface}...")

    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)

    # Send DCP identify request
    send_discover(sock, src_mac, device_name)

    # Wait for response
    responses = read_response(sock, timeout=3.0)

    sock.close()

    if not responses:
        raise RuntimeError(f"Device '{device_name}' not found")

    # Return first matching device
    for resp in responses:
        if resp.name_of_station.lower() == device_name.lower():
            return resp
        # Also match by MAC
        if device_name.lower().replace(":", "") in resp.mac.lower().replace(":", ""):
            return resp

    raise RuntimeError(f"Device '{device_name}' not found in {len(responses)} responses")


def main():
    global running

    if not DEVICE:
        print("Usage: sudo PROFINET_DEVICE=<name_or_mac> python3 18_cyclic_io.py")
        print("  Or:  sudo PROFINET_IFACE=eth0 PROFINET_DEVICE=my-device python3 18_cyclic_io.py")
        print("\nEnvironment variables:")
        print("  PROFINET_IFACE      - Network interface (default: eth0)")
        print("  PROFINET_DEVICE     - Device name or MAC address")
        print("  PROFINET_CYCLE_MS   - Cycle time in ms (default: 32)")
        print("\n*** PYTHON TIMING WARNING ***")
        print("Python has timing limitations due to GIL and OS scheduling:")
        print("  32ms+  : Reliable on all systems (RECOMMENDED)")
        print("  8-16ms : Usually works, minor jitter possible")
        print("  <8ms   : NOT RECOMMENDED - timing issues likely")
        print("  <1ms   : IMPOSSIBLE in Python - use C/C++ instead")
        sys.exit(1)

    # Warn if cycle time is too low
    if CYCLE_TIME_MS < 8:
        print(f"\n*** WARNING: Cycle time {CYCLE_TIME_MS}ms is below 8ms! ***")
        print("Python cannot reliably achieve this timing. Expect failures.")
        print("Consider using PROFINET_CYCLE_MS=32 for reliable operation.\n")

    signal.signal(signal.SIGINT, signal_handler)

    # Step 1: Discover device
    try:
        device = discover_device(INTERFACE, DEVICE)
        print(f"Found: {device.name_of_station} at {device.ip}")
        print(f"  MAC: {device.mac}")
        print(f"  Vendor: {device.vendor_id:04X} Device: {device.device_id:04X}")
    except Exception as e:
        print(f"Discovery failed: {e}")
        sys.exit(1)

    # Step 2: Configure IOCR
    # NOTE: These slot/subslot values must match your actual device!
    # You can discover available slots using example 05_discover_topology.py
    print("\nConfiguring IOCR...")

    # Calculate timing factors
    # Cycle time = send_clock_factor * reduction_ratio * 31.25us
    # For 8ms: 32 * 8 * 31.25us = 8000us = 8ms
    send_clock_factor = 32  # 1ms base (31.25us * 32 = 1ms)
    reduction_ratio = CYCLE_TIME_MS

    print(f"  Cycle time: {CYCLE_TIME_MS}ms")
    print(f"  send_clock_factor: {send_clock_factor}")
    print(f"  reduction_ratio: {reduction_ratio}")

    # Example slot configuration (adjust for your device)
    # This is a common configuration for a simple IO device:
    iocr_setup = IOCRSetup(
        slots=[
            # DAP (Device Access Point) - slot 0, subslot 1
            # Usually has status info but no process data
            IOSlot(
                slot=0,
                subslot=1,
                module_ident=0x00003010,  # DAP module
                submodule_ident=0x00003010,
                input_length=0,
                output_length=0,
            ),
            # IO Module - slot 1, subslot 1
            # Example: 8 bytes output
            IOSlot(
                slot=1,
                subslot=1,
                module_ident=0x10000000,  # Example module ID
                submodule_ident=0x20000000,  # Example submodule ID
                input_length=0,
                output_length=8,
            ),
        ],
        send_clock_factor=send_clock_factor,
        reduction_ratio=reduction_ratio,
        watchdog_factor=3,
        data_hold_factor=3,
    )

    # Step 3: Connect with IOCR
    print("\nConnecting to device with IOCR...")

    src_mac = bytes.fromhex(get_mac(INTERFACE).replace(":", ""))
    dst_mac = bytes.fromhex(device.mac.replace(":", ""))

    try:
        rpc = RPCCon(
            device.ip,
            interface=INTERFACE,
            mac=dst_mac,
        )

        result = rpc.connect(
            src_mac=src_mac,
            with_alarm_cr=False,  # AlarmCR often causes issues
            iocr_setup=iocr_setup,
        )

        if result:
            print("Connected with IOCR!")
            print(f"  Input Frame ID:  0x{result.input_frame_id:04X}")
            print(f"  Output Frame ID: 0x{result.output_frame_id:04X}")
        else:
            print("Connected (no IOCR result)")

    except Exception as e:
        print(f"Connect failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Step 4: Parameter phase
    print("\nParameter phase...")
    try:
        rpc.prm_begin()
        print("  PrmBegin OK")

        # Here you would write device parameters if needed
        # rpc.write(api, slot, subslot, index, data)

        rpc.prm_end()
        print("  PrmEnd OK")
    except Exception as e:
        print(f"Parameter phase failed: {e}")
        rpc.close()
        sys.exit(1)

    # Step 5: Application Ready
    print("\nSignaling ApplicationReady...")
    try:
        rpc.application_ready()
        print("  ApplicationReady OK - Device should enter RUN state")
    except Exception as e:
        print(f"ApplicationReady failed: {e}")
        # This is often expected if device is not properly configured
        print("  (Device may not support cyclic IO or needs proper configuration)")

    # Step 6: Start cyclic data exchange
    if result and result.output_frame_id > 0:
        print("\nStarting cyclic data exchange...")

        # Build IOCR configs from setup
        output_iocr = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=result.output_frame_id,
            send_clock_factor=send_clock_factor,
            reduction_ratio=reduction_ratio,
            data_length=48,  # Minimum padded length
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8),
            ],
        )

        input_iocr = IOCRConfig(
            iocr_type=IOCR_TYPE_INPUT,
            iocr_reference=2,
            frame_id=result.input_frame_id,
            send_clock_factor=send_clock_factor,
            reduction_ratio=reduction_ratio,
            data_length=48,
            objects=[],  # No input objects in this example
        )

        cyclic = CyclicController(
            interface=INTERFACE,
            src_mac=src_mac,
            dst_mac=dst_mac,
            input_iocr=input_iocr,
            output_iocr=output_iocr,
        )

        # Set initial output data
        cyclic.set_output_data(1, 1, bytes(8))  # 8 zero bytes

        # Start cyclic threads
        cyclic.start()
        print(f"Cyclic exchange running at {CYCLE_TIME_MS}ms cycle time")
        print("Press Ctrl+C to stop.\n")

        # Main loop - update outputs periodically
        counter = 0
        while running:
            time.sleep(0.1)
            counter = (counter + 1) % 256

            # Update output data (example: incrementing counter)
            output_data = bytes([counter] * 8)
            cyclic.set_output_data(1, 1, output_data)

            # Print stats every 5 seconds
            if counter % 50 == 0:
                print(
                    f"Stats: TX={cyclic.stats.frames_sent}, "
                    f"RX={cyclic.stats.frames_received}, "
                    f"Missed={cyclic.stats.frames_missed}"
                )

        # Stop cyclic
        print("\nStopping cyclic exchange...")
        cyclic.stop()
        print(
            f"Final stats: TX={cyclic.stats.frames_sent}, "
            f"RX={cyclic.stats.frames_received}, "
            f"Missed={cyclic.stats.frames_missed}"
        )

    else:
        print("\nNo IOCR established - cyclic IO not available")
        print("Keeping connection open for 10 seconds...")
        for _i in range(10):
            if not running:
                break
            time.sleep(1)

    # Cleanup
    print("\nDisconnecting...")
    rpc.close()
    print("Done.")


if __name__ == "__main__":
    main()
