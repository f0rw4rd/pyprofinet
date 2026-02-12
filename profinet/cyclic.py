"""
PROFINET Cyclic IO Controller.

Provides RT_CLASS_1 cyclic data exchange with PROFINET devices:
- Periodic output frame transmission to device
- Input frame reception from device
- Watchdog timeout detection
- Statistics tracking

Per IEC 61158-6-10:
- Uses EtherType 0x8892
- Frame IDs 0xC000-0xFBFF for RT_CLASS_1

WARNING: EXPERIMENTAL - NOT TESTED WITH REAL DEVICES
=====================================================
This module has NOT been tested with real PROFINET devices.
The cyclic IO exchange may not work correctly. Use at your
own risk. Contributions and test reports are welcome.

WARNING: Python Timing Limitations
==================================
Due to Python's Global Interpreter Lock (GIL) and OS scheduling jitter,
reliable cyclic timing is LIMITED in pure Python:

- MINIMUM practical cycle time: 8ms (may have jitter under load)
- RECOMMENDED cycle time: 32ms or higher for reliable operation
- Sub-millisecond timing: NOT POSSIBLE in Python

For faster cycle times, use:
- C/C++ with real-time OS (PREEMPT_RT Linux)
- Hardware-based PROFINET controllers
- FPGA/ASIC implementations

RT_CLASS_3 (IRT/isochronous) requires hardware support
and is not achievable in pure Python.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .rt import (
    _ETHERTYPE_PROFINET_BYTES,
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    ETHERTYPE_PROFINET,
    IOXS_GOOD,
    CyclicDataBuilder,
    EtherTypeStruct,
    IOCRConfig,
    RTFrame,
)
from .util import ethernet_socket as _ethernet_socket

logger = logging.getLogger(__name__)


@dataclass
class CyclicStats:
    """Statistics for cyclic communication.

    Tracks frame counts, timing, and errors.
    """

    frames_sent: int = 0
    """Total output frames transmitted."""

    frames_received: int = 0
    """Total input frames received."""

    frames_missed: int = 0
    """Number of watchdog timeouts (missed frames)."""

    frames_invalid: int = 0
    """Number of received frames with invalid status."""

    last_cycle_time_us: int = 0
    """Actual cycle time of last transmission (microseconds)."""

    max_jitter_us: int = 0
    """Maximum observed jitter (deviation from target cycle)."""

    last_receive_time: float = 0.0
    """Timestamp of last received frame (time.perf_counter)."""

    def reset(self) -> None:
        """Reset all statistics to zero."""
        self.frames_sent = 0
        self.frames_received = 0
        self.frames_missed = 0
        self.frames_invalid = 0
        self.last_cycle_time_us = 0
        self.max_jitter_us = 0


# Minimum recommended cycle time for Python
PYTHON_MIN_CYCLE_MS = 8
PYTHON_RECOMMENDED_CYCLE_MS = 32


class CyclicController:
    """RT_CLASS_1 cyclic data exchange controller.

    Manages bidirectional cyclic IO communication with a PROFINET device:
    - TX thread sends output data to device at configured rate
    - RX thread receives and processes input data from device
    - Watchdog detects communication failures

    Example:
        >>> controller = CyclicController(
        ...     interface="eth0",
        ...     src_mac=controller_mac,
        ...     dst_mac=device_mac,
        ...     input_iocr=input_config,
        ...     output_iocr=output_config,
        ... )
        >>> controller.on_input(lambda s, ss, d: print(f"Data from {s}:{ss}"))
        >>> controller.start()
        >>> controller.set_output_data(1, 1, b"\\x01\\x02\\x03\\x04")
        >>> # ... let it run ...
        >>> controller.stop()

    Warning:
        Python timing limitations apply! Recommended cycle times:
        - 32ms+: Reliable on all systems
        - 8-16ms: Works on most systems with low load
        - <8ms: NOT RECOMMENDED - expect jitter and missed frames
        - <1ms: NOT POSSIBLE in Python
    """

    def __init__(
        self,
        interface: str,
        src_mac: bytes,
        dst_mac: bytes,
        input_iocr: IOCRConfig,
        output_iocr: IOCRConfig,
    ):
        """Initialize cyclic controller.

        Args:
            interface: Network interface name (e.g., "eth0")
            src_mac: Controller MAC address (6 bytes)
            dst_mac: Device MAC address (6 bytes)
            input_iocr: IOCR config for input data (device -> controller)
            output_iocr: IOCR config for output data (controller -> device)

        Warns:
            If cycle time is below recommended minimum for Python.
        """
        self.interface = interface
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.input_iocr = input_iocr
        self.output_iocr = output_iocr

        self._running = False
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

        # Cycle state
        self._cycle_counter = 0
        self._output_builder = CyclicDataBuilder(output_iocr)
        self._input_data: Dict[Tuple[int, int], bytes] = {}
        self._data_lock = threading.Lock()

        # Check and warn about cycle time
        self._check_cycle_time()

        # Initialize all IOPS to good
        self._output_builder.set_all_iops(IOXS_GOOD)

        # Callbacks
        self._on_input_data: Optional[Callable[[int, int, bytes], None]] = None
        self._on_timeout: Optional[Callable[[], None]] = None
        self._on_error: Optional[Callable[[str], None]] = None

        # Statistics
        self.stats = CyclicStats()

    def _check_cycle_time(self) -> None:
        """Check cycle time and log warnings if too fast for Python."""
        cycle_ms = self.output_iocr.cycle_time_ms

        if cycle_ms < 1:
            raise ValueError(
                f"Cycle time {cycle_ms:.2f}ms is below 1ms — not achievable in "
                f"Python. Use a C/FPGA-based controller for sub-millisecond cycles."
            )
        elif cycle_ms < PYTHON_MIN_CYCLE_MS:
            import warnings

            warnings.warn(
                f"Cycle time {cycle_ms:.0f}ms is below the recommended "
                f"{PYTHON_MIN_CYCLE_MS}ms minimum for Python. "
                f"Expect jitter and missed frames. "
                f"Use {PYTHON_RECOMMENDED_CYCLE_MS}ms+ for reliable operation.",
                stacklevel=3,
            )

    def set_output_data(self, slot: int, subslot: int, data: bytes) -> None:
        """Set output data for next cycle.

        Thread-safe - can be called from any thread.

        Args:
            slot: Slot number
            subslot: Subslot number
            data: Process data bytes
        """
        with self._data_lock:
            self._output_builder.set_data(slot, subslot, data)
            self._output_builder.set_iops(slot, subslot, IOXS_GOOD)

    def get_input_data(self, slot: int, subslot: int) -> Optional[bytes]:
        """Get latest input data from device.

        Thread-safe - can be called from any thread.

        Args:
            slot: Slot number
            subslot: Subslot number

        Returns:
            Latest input data bytes, or None if not received
        """
        with self._data_lock:
            return self._input_data.get((slot, subslot))

    def on_input(self, callback: Callable[[int, int, bytes], None]) -> None:
        """Register callback for input data updates.

        Callback is invoked from RX thread for each received data update.

        Args:
            callback: Function(slot, subslot, data) called on input
        """
        self._on_input_data = callback

    def on_timeout(self, callback: Callable[[], None]) -> None:
        """Register callback for watchdog timeout.

        Called when no input frame received within watchdog time.

        Args:
            callback: Function called on timeout
        """
        self._on_timeout = callback

    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register callback for communication errors.

        Args:
            callback: Function(error_message) called on error
        """
        self._on_error = callback

    def start(self) -> None:
        """Start cyclic data exchange.

        Creates raw socket and spawns TX/RX threads.
        """
        if self._running:
            return

        self._running = True
        self.stats.reset()
        self._sock = self._create_raw_socket()

        # Start TX thread
        self._tx_thread = threading.Thread(
            target=self._tx_loop,
            daemon=True,
            name=f"CyclicTX-{self.interface}",
        )
        self._tx_thread.start()

        # Start RX thread
        self._rx_thread = threading.Thread(
            target=self._rx_loop,
            daemon=True,
            name=f"CyclicRX-{self.interface}",
        )
        self._rx_thread.start()

        logger.info(
            f"Cyclic controller started on {self.interface} "
            f"(cycle={self.output_iocr.cycle_time_ms:.1f}ms)"
        )

    def stop(self) -> None:
        """Stop cyclic exchange.

        Signals threads to stop and waits for shutdown.
        """
        if not self._running:
            return

        self._running = False

        # Close socket to unblock recv
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

        # Wait for threads
        if self._tx_thread and self._tx_thread.is_alive():
            self._tx_thread.join(timeout=2.0)
        if self._rx_thread and self._rx_thread.is_alive():
            self._rx_thread.join(timeout=2.0)

        self._sock = None
        self._tx_thread = None
        self._rx_thread = None

        logger.info(
            f"Cyclic controller stopped "
            f"(sent={self.stats.frames_sent}, recv={self.stats.frames_received})"
        )

    @property
    def is_running(self) -> bool:
        """True if controller is currently running."""
        return self._running

    def _create_raw_socket(self):
        """Create raw Ethernet socket.

        Uses platform-abstracted ethernet_socket() from util (AF_PACKET on
        Linux, NpcapSocket on Windows, PcapSocket on macOS).

        Returns:
            Configured socket

        Raises:
            PermissionError: If raw socket requires root/admin privileges
        """
        try:
            sock = _ethernet_socket(self.interface, ETHERTYPE_PROFINET)
        except PermissionError as e:
            raise PermissionError(f"Raw socket requires root/admin privileges: {e}") from e

        # Non-blocking with short timeout for RX
        sock.settimeout(0.001)  # 1ms
        return sock

    def _tx_loop(self) -> None:
        """Transmit loop - sends output frames at cycle rate."""
        cycle_time_s = self.output_iocr.cycle_time_us / 1_000_000
        next_send = time.perf_counter()
        last_send = next_send

        logger.debug(f"TX thread started, cycle={cycle_time_s * 1000:.2f}ms")

        while self._running:
            now = time.perf_counter()

            if now >= next_send:
                self._send_output_frame()
                self.stats.frames_sent += 1

                # Calculate actual cycle time and jitter
                actual_us = int((now - last_send) * 1_000_000)
                self.stats.last_cycle_time_us = actual_us
                jitter = abs(actual_us - self.output_iocr.cycle_time_us)
                if jitter > self.stats.max_jitter_us:
                    self.stats.max_jitter_us = jitter

                last_send = now

                # Calculate next send time
                next_send += cycle_time_s

                # If we're behind, catch up
                if next_send < now:
                    missed = int((now - next_send) / cycle_time_s)
                    next_send = now + cycle_time_s
                    if missed > 0:
                        logger.warning(f"TX: missed {missed} cycles")

            # Sleep until next cycle
            sleep_time = next_send - time.perf_counter() - 0.0001
            if sleep_time > 0:
                time.sleep(sleep_time)

        logger.debug("TX thread stopped")

    def _send_output_frame(self) -> None:
        """Build and send output RT frame."""
        self._cycle_counter = (self._cycle_counter + 1) & 0xFFFF

        with self._data_lock:
            payload = self._output_builder.build()

        # Build RT frame with good status
        data_status = (
            DATA_STATUS_VALID
            | DATA_STATUS_PROVIDER_RUN
            | DATA_STATUS_STATION_OK
            | DATA_STATUS_STATE
        )

        frame = RTFrame(
            frame_id=self.output_iocr.frame_id,
            cycle_counter=self._cycle_counter,
            data_status=data_status,
            transfer_status=0x00,
            payload=payload,
        )

        # Build Ethernet frame
        eth_frame = self.dst_mac + self.src_mac + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()

        try:
            self._sock.send(eth_frame)
        except Exception as e:
            logger.error(f"TX error: {e}")
            if self._on_error:
                self._on_error(f"TX error: {e}")

    def _rx_loop(self) -> None:
        """Receive loop - processes input frames from device."""
        watchdog_s = self.input_iocr.watchdog_time_us / 1_000_000
        self.stats.last_receive_time = time.perf_counter()

        logger.debug(f"RX thread started, watchdog={watchdog_s * 1000:.1f}ms")

        while self._running:
            try:
                data = self._sock.recv(4096)
                self._process_input_frame(data)

            except TimeoutError:
                # Check watchdog
                elapsed = time.perf_counter() - self.stats.last_receive_time
                if elapsed > watchdog_s:
                    self.stats.frames_missed += 1
                    if self._on_timeout:
                        try:
                            self._on_timeout()
                        except Exception as e:
                            logger.error(f"Timeout callback error: {e}")
                    # Reset timer
                    self.stats.last_receive_time = time.perf_counter()
                continue

            except OSError:
                # Socket closed
                if self._running:
                    logger.error("RX: Socket closed unexpectedly")
                break

            except Exception as e:
                logger.error(f"RX error: {e}")
                if self._on_error:
                    self._on_error(f"RX error: {e}")

        logger.debug("RX thread stopped")

    def _process_input_frame(self, data: bytes) -> None:
        """Parse and process received RT frame.

        Args:
            data: Raw Ethernet frame
        """
        if len(data) < 18:
            return

        # Parse Ethernet header
        src_mac = data[6:12]
        ethertype = EtherTypeStruct.parse(data[12:14]).ethertype

        if ethertype != ETHERTYPE_PROFINET:
            return

        # Filter by device MAC
        if src_mac != self.dst_mac:
            return

        try:
            frame = RTFrame.from_bytes(data[14:])
        except ValueError:
            return

        # Check frame ID matches our input IOCR
        if frame.frame_id != self.input_iocr.frame_id:
            return

        # Update receive time
        self.stats.last_receive_time = time.perf_counter()
        self.stats.frames_received += 1

        # Check validity
        if not frame.is_valid:
            self.stats.frames_invalid += 1
            return

        # Extract data per IO object
        with self._data_lock:
            for obj in self.input_iocr.objects:
                if obj.frame_offset + obj.data_length <= len(frame.payload):
                    obj_data = frame.payload[obj.frame_offset : obj.frame_offset + obj.data_length]
                    self._input_data[(obj.slot, obj.subslot)] = obj_data

                    if self._on_input_data:
                        try:
                            self._on_input_data(obj.slot, obj.subslot, obj_data)
                        except Exception as e:
                            logger.error(f"Input callback error: {e}")

    def __enter__(self) -> CyclicController:
        """Context manager entry - start controller."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit - stop controller."""
        self.stop()

    def __repr__(self) -> str:
        status = "running" if self._running else "stopped"
        return (
            f"CyclicController({self.interface}, "
            f"out_id=0x{self.output_iocr.frame_id:04X}, "
            f"in_id=0x{self.input_iocr.frame_id:04X}, "
            f"{status})"
        )
