"""
PROFINET DCE/RPC client implementation.

Provides IO-Controller functionality:
- RPCCon: Connection class for PROFINET IO communication
- get_station_info(): Resolve device name to connection info
- Read/Write operations via slot/subslot/index addressing

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from socket import AF_INET, SOCK_DGRAM, socket
from socket import timeout as SocketTimeout
from struct import pack, unpack
from typing import Any, Dict, List, Optional, Tuple

from . import blocks, dcp, indices
from .blocks import (
    ExpectedSubmoduleBlockReq,
    IODWriteMultipleBuilder,
    ModuleDiffBlock,
    WriteMultipleResult,
    parse_module_diff_block,
    parse_write_multiple_response,
)
from .diagnosis import (
    DiagnosisData,
    parse_diagnosis_block,
    parse_diagnosis_simple,
)
from .exceptions import (
    DCPDeviceNotFoundError,
    PNIOError,
    RPCConnectionError,
    RPCError,
    RPCFaultError,
    RPCTimeoutError,
)
from .protocol import (
    IOCRAPIObject,
    PNAlarmCRBlockReq,
    PNAlarmCRBlockRes,
    PNARBlockRequest,
    PNBlockHeader,
    PNDCPBlock,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNInM4,
    PNInM5,
    PNInM6,
    PNInM7,
    PNInM8,
    PNInM9,
    PNInM10,
    PNInM11,
    PNInM12,
    PNInM13,
    PNInM14,
    PNInM15,
    PNIOCRBlockReqHeader,
    PNIOCRBlockRes,
    PNIODHeader,
    PNIODReleaseBlock,
    PNNRDData,
    PNRPCHeader,
)

# =============================================================================
# Data Classes for Parsed Records
# =============================================================================


@dataclass
class PortStatistics:
    """Port statistics data (0x8028)."""
    ifInOctets: int = 0
    ifOutOctets: int = 0
    ifInDiscards: int = 0
    ifOutDiscards: int = 0
    ifInErrors: int = 0
    ifOutErrors: int = 0


@dataclass
class LinkData:
    """Port link data (0x8029)."""
    link_state: str = "unknown"
    link_speed: int = 0
    mau_type: int = 0
    mau_type_name: str = "unknown"


@dataclass
class PortInfo:
    """Port information from PDPortDataReal."""
    slot: int = 0
    subslot: int = 0
    port_id: str = ""
    peer_port_id: str = ""
    peer_chassis_id: str = ""
    peer_mac: str = ""
    mau_type: int = 0
    link_state: int = 0
    line_delay_ns: int = 0


@dataclass
class InterfaceInfo:
    """Interface information from PDInterfaceDataReal."""
    chassis_id: str = ""
    mac: str = ""
    ip: str = ""
    netmask: str = ""
    gateway: str = ""


@dataclass
class DiagnosisEntry:
    """Single diagnosis entry."""
    channel: int = 0
    error_type: int = 0
    ext_error_type: int = 0
    add_value: int = 0


@dataclass
class ARInfo:
    """Application Relationship info (0xF820)."""
    ar_uuid: str = ""
    ar_type: int = 0
    ar_properties: int = 0
    session_key: int = 0


@dataclass
class LogEntry:
    """Log book entry (0xF830)."""
    timestamp: int = 0
    entry_detail: int = 0


# MAU type mapping
MAU_TYPES = {
    0: "Unknown",
    10: "10BASE-T HD",
    11: "10BASE-T FD",
    15: "100BASE-TX HD",
    16: "100BASE-TX FD",
    17: "100BASE-FX HD",
    18: "100BASE-FX FD",
    29: "1000BASE-T HD",
    30: "1000BASE-T FD",
    21: "1000BASE-X HD",
    22: "1000BASE-X FD",
    40: "10GBASE-T",
}

logger = logging.getLogger(__name__)

# RPC ports (IEC 61158-6-10)
RPC_PORT = 0x8894  # 34964 - PROFINET IO RPC port
RPC_BIND_PORT = 0x8895  # 34965 - PROFINET IO RPC bind port

# RPC UUIDs (DCE/RPC standard)
UUID_NULL = "00000000-0000-0000-0000-000000000000"
UUID_EPM_V4 = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"  # Endpoint Mapper
UUID_PNIO_DEVICE = "dea00001-6c97-11d1-8271-00a02442df7d"  # PROFINET IO Device
UUID_PNIO_CONTROLLER = "dea00002-6c97-11d1-8271-00a02442df7d"  # PROFINET IO Controller

# PNIO Device Interface Version
PNIO_DEVICE_INTERFACE_VERSION = 1

# EPM constants
EPM_LOOKUP = 0x02  # ept_lookup operation
EPM_INQUIRY_ALL = 0x00  # Return all entries
EPM_INQUIRY_INTERFACE = 0x01  # Filter by interface UUID

DEFAULT_TIMEOUT = 5.0
CONNECTION_TIMEOUT = 10


# =============================================================================
# EPM (Endpoint Mapper) Data Classes and Functions
# =============================================================================


@dataclass
class EPMEndpoint:
    """Parsed EPM endpoint entry.

    Represents a single RPC endpoint discovered via Endpoint Mapper lookup.
    """

    interface_uuid: str = ""
    interface_version_major: int = 0
    interface_version_minor: int = 0
    object_uuid: str = ""
    protocol: str = ""
    port: int = 0
    address: str = ""
    annotation: str = ""  # Device model/article number from EPM response

    @property
    def interface_name(self) -> str:
        """Get human-readable interface name."""
        names = {
            UUID_PNIO_DEVICE.lower(): "PNIO-Device",
            UUID_PNIO_CONTROLLER.lower(): "PNIO-Controller",
            "dea00003-6c97-11d1-8271-00a02442df7d": "PNIO-Supervisor",
            "dea00004-6c97-11d1-8271-00a02442df7d": "PNIO-ParameterServer",
            UUID_EPM_V4.lower(): "EPM",
        }
        return names.get(self.interface_uuid.lower(), f"Unknown({self.interface_uuid})")


def _uuid_bytes_to_string(data: bytes) -> str:
    """Convert 16-byte UUID to string format.

    DCE/RPC UUIDs are stored in mixed-endian format:
    - First 3 fields are little-endian
    - Last 2 fields are big-endian
    """
    if len(data) != 16:
        return ""

    # Parse fields (little-endian for first 3, big-endian for rest)
    time_low = int.from_bytes(data[0:4], "little")
    time_mid = int.from_bytes(data[4:6], "little")
    time_hi = int.from_bytes(data[6:8], "little")
    clock_seq = int.from_bytes(data[8:10], "big")
    node = data[10:16].hex()

    return f"{time_low:08x}-{time_mid:04x}-{time_hi:04x}-{clock_seq:04x}-{node}"


def _string_to_uuid_bytes(uuid_str: str) -> bytes:
    """Convert UUID string to 16-byte DCE/RPC format (mixed-endian)."""
    parts = uuid_str.replace("-", "")
    if len(parts) != 32:
        raise ValueError(f"Invalid UUID string: {uuid_str}")

    # Parse hex parts
    time_low = int(parts[0:8], 16)
    time_mid = int(parts[8:12], 16)
    time_hi = int(parts[12:16], 16)
    clock_seq = int(parts[16:20], 16)
    node = bytes.fromhex(parts[20:32])

    # Pack in mixed-endian format
    result = bytearray()
    result.extend(time_low.to_bytes(4, "little"))
    result.extend(time_mid.to_bytes(2, "little"))
    result.extend(time_hi.to_bytes(2, "little"))
    result.extend(clock_seq.to_bytes(2, "big"))
    result.extend(node)

    return bytes(result)


def _parse_epm_tower(tower_data: bytes) -> Optional[EPMEndpoint]:
    """Parse an EPM tower structure to extract endpoint info.

    Tower format (simplified):
    - Floor count (2 bytes)
    - For each floor:
      - LHS length (2 bytes)
      - LHS data (protocol identifier + data)
      - RHS length (2 bytes)
      - RHS data (address data)

    Floor protocols:
    - 0x0D: UUID (interface)
    - 0x0D: UUID (transfer syntax)
    - 0x0A: RPC connectionless (ncadg)
    - 0x08: UDP
    - 0x09: IP
    """
    if len(tower_data) < 4:
        return None

    try:
        offset = 0
        floor_count = int.from_bytes(tower_data[offset : offset + 2], "little")
        offset += 2

        endpoint = EPMEndpoint()

        for floor_idx in range(floor_count):
            if offset + 4 > len(tower_data):
                break

            # LHS (left-hand side) - protocol identifier
            lhs_len = int.from_bytes(tower_data[offset : offset + 2], "little")
            offset += 2

            if offset + lhs_len > len(tower_data):
                break

            lhs_data = tower_data[offset : offset + lhs_len]
            offset += lhs_len

            # RHS (right-hand side) - address data
            if offset + 2 > len(tower_data):
                break

            rhs_len = int.from_bytes(tower_data[offset : offset + 2], "little")
            offset += 2

            if offset + rhs_len > len(tower_data):
                break

            rhs_data = tower_data[offset : offset + rhs_len]
            offset += rhs_len

            # Parse floor based on protocol ID
            if lhs_len >= 1:
                protocol_id = lhs_data[0]

                if protocol_id == 0x0D and lhs_len >= 19:
                    # UUID floor (interface or transfer syntax)
                    uuid_bytes = lhs_data[1:17]
                    version_major = int.from_bytes(lhs_data[17:19], "little")

                    if floor_idx == 0:
                        # First UUID floor is the interface
                        endpoint.interface_uuid = _uuid_bytes_to_string(uuid_bytes)
                        endpoint.interface_version_major = version_major
                        if rhs_len >= 2:
                            endpoint.interface_version_minor = int.from_bytes(
                                rhs_data[0:2], "little"
                            )

                elif protocol_id == 0x0A:
                    # RPC connectionless (ncadg_ip_udp)
                    endpoint.protocol = "ncadg_ip_udp"

                elif protocol_id == 0x08 and rhs_len >= 2:
                    # UDP port
                    endpoint.port = int.from_bytes(rhs_data[0:2], "big")

                elif protocol_id == 0x09 and rhs_len >= 4:
                    # IP address
                    endpoint.address = ".".join(str(b) for b in rhs_data[0:4])

        return endpoint if endpoint.interface_uuid else None

    except Exception as e:
        logger.debug(f"Failed to parse EPM tower: {e}")
        return None


# =============================================================================
# IOCR (Cyclic IO) Configuration Data Classes
# =============================================================================


@dataclass
class IOSlot:
    """Single IO slot/subslot for cyclic data exchange."""

    slot: int
    """Slot number."""

    subslot: int
    """Subslot number."""

    input_length: int = 0
    """Input data length (device -> controller). 0 = no input."""

    output_length: int = 0
    """Output data length (controller -> device). 0 = no output."""

    module_ident: int = 0
    """Module identification number (from device discovery)."""

    submodule_ident: int = 0
    """Submodule identification number (from device discovery)."""


# Minimum recommended cycle time for Python (due to GIL and OS scheduling)
PYTHON_MIN_CYCLE_TIME_MS = 8

# Safe default cycle time that works reliably with Python
PYTHON_SAFE_CYCLE_TIME_MS = 32


@dataclass
class IOCRSetup:
    """Configuration for IOCR (IO Connection Relationship) setup.

    Used to configure cyclic IO exchange when establishing an AR.

    WARNING: EXPERIMENTAL - NOT TESTED WITH REAL DEVICES
    =====================================================
    This feature has NOT been tested with real PROFINET devices.
    The IOCR block building and cyclic IO exchange may not work
    correctly. Use at your own risk. Contributions and test
    reports are welcome.

    WARNING: Python Timing Limitations
    ==================================
    Due to Python's Global Interpreter Lock (GIL) and OS scheduling,
    reliable cyclic IO timing below 8ms is NOT achievable in pure Python.

    Recommended cycle times:
    - 32ms (default): Safe, works reliably on all systems
    - 16ms: Works on most systems with low CPU load
    - 8ms:  Minimum practical value, may have jitter under load

    Cycle times below 8ms will likely result in:
    - Missed frames and watchdog timeouts
    - High CPU usage from busy-waiting
    - Unstable communication with the device

    For sub-millisecond timing, use hardware-based solutions or
    real-time operating systems with C/C++ implementations.
    """

    slots: List[IOSlot]
    """List of IO slots to include in cyclic exchange."""

    send_clock_factor: int = 32
    """Base clock multiplier. 32 = 1ms base clock (31.25µs * 32 = 1ms).
    Do not change unless you understand PROFINET timing requirements."""

    reduction_ratio: int = 32
    """Cycle time = send_clock_factor * reduction_ratio * 31.25µs.
    Default: 32 * 32 * 31.25µs = 32ms (safe for Python).

    Common values:
    - 32: 32ms cycle (default, recommended for Python)
    - 16: 16ms cycle
    - 8:  8ms cycle (minimum practical for Python)
    - 4:  4ms cycle (may have issues in Python)
    - 1:  1ms cycle (NOT recommended for Python - use C/C++)
    """

    watchdog_factor: int = 6
    """Watchdog timeout = watchdog_factor * cycle_time.
    Default: 6 (gives 192ms timeout with 32ms cycle).
    Higher values tolerate more jitter but slower failure detection."""

    data_hold_factor: int = 6
    """Data hold time = data_hold_factor * cycle_time.
    Default: 6 (matches watchdog for consistency)."""

    @property
    def cycle_time_us(self) -> int:
        """Calculate cycle time in microseconds."""
        return (self.reduction_ratio * self.send_clock_factor * 125) // 4

    @property
    def cycle_time_ms(self) -> float:
        """Calculate cycle time in milliseconds."""
        return self.cycle_time_us / 1000.0

    def validate(self) -> List[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        cycle_ms = self.cycle_time_ms

        if cycle_ms < 1:
            warnings.append(f"Cycle {cycle_ms:.2f}ms too fast - Python can't do <1ms")
        elif cycle_ms < PYTHON_MIN_CYCLE_TIME_MS:
            warnings.append(f"Cycle {cycle_ms:.0f}ms may cause jitter (use {PYTHON_MIN_CYCLE_TIME_MS}ms+)")

        if self.watchdog_factor < 3:
            warnings.append(f"Watchdog factor {self.watchdog_factor} too low (use 6+)")

        if not self.slots:
            warnings.append("No IO slots configured")

        return warnings

    def __post_init__(self):
        """Log warnings after initialization."""
        for warning in self.validate():
            logger.warning(f"IOCRSetup: {warning}")


@dataclass
class ConnectResult:
    """Result from AR CONNECT with IOCR support."""

    ar_uuid: bytes = b""
    """AR UUID assigned by device."""

    session_key: int = 0
    """Session key for this AR."""

    input_frame_id: int = 0
    """Frame ID for input IOCR (device -> controller). 0 = not established."""

    output_frame_id: int = 0
    """Frame ID for output IOCR (controller -> device). 0 = not established."""

    device_alarm_ref: int = 0
    """Device's alarm reference (if AlarmCR established)."""

    @property
    def has_cyclic(self) -> bool:
        """True if cyclic IO was established."""
        return self.input_frame_id != 0 or self.output_frame_id != 0


def epm_lookup(
    ip: str,
    port: int = RPC_PORT,
    timeout: float = 5.0,
    interface_filter: Optional[str] = None,
) -> List[EPMEndpoint]:
    """Query Endpoint Mapper for available RPC endpoints.

    Sends an EPM lookup request to discover what RPC services
    are available on a PROFINET device.

    Args:
        ip: Target IP address
        port: RPC port (default: 34964)
        timeout: Response timeout in seconds
        interface_filter: Optional interface UUID to filter results

    Returns:
        List of EPMEndpoint objects describing available services

    Example:
        >>> endpoints = epm_lookup("192.168.1.100")
        >>> for ep in endpoints:
        ...     print(f"{ep.interface_name}: port {ep.port}")
        PNIO-Device: port 34964
    """
    import os
    import struct

    # Build EPM lookup request
    # RPC header
    version = 4
    packet_type = 0x00  # REQUEST
    flags1 = 0x20  # Idempotent
    flags2 = 0x00
    drep = bytes([0x10, 0x00, 0x00])  # Little-endian, ASCII, IEEE float

    # Generate random UUIDs for activity and object
    activity_uuid = os.urandom(16)
    object_uuid = bytes(16)  # NULL object UUID

    # EPM interface UUID (little-endian format for DCE/RPC)
    interface_uuid = _string_to_uuid_bytes(UUID_EPM_V4)

    # Build RPC header (80 bytes)
    rpc_header = struct.pack(
        "<BBBB3sB16s16s16sIIIHHHHHBB",
        version,  # version
        packet_type,  # packet_type
        flags1,  # flags1
        flags2,  # flags2
        drep,  # drep
        0,  # serial_high
        object_uuid,  # object_uuid
        interface_uuid,  # interface_uuid
        activity_uuid,  # activity_uuid
        0,  # server_boot_time
        3,  # interface_version (major=3, minor=0 for EPM)
        0,  # sequence_number
        EPM_LOOKUP,  # operation_number (2 = ept_lookup)
        0xFFFF,  # interface_hint
        0xFFFF,  # activity_hint
        0,  # length_of_body (filled later)
        0,  # fragment_number
        0,  # authentication_protocol
        0,  # serial_low
    )

    # EPM lookup request body
    # inquiry_type: 0 = all, 1 = by interface
    inquiry_type = EPM_INQUIRY_INTERFACE if interface_filter else EPM_INQUIRY_ALL

    # Object UUID (NULL)
    object_uuid_body = bytes(16)

    # Interface UUID filter (or NULL for all)
    if interface_filter:
        iface_uuid_body = _string_to_uuid_bytes(interface_filter)
        iface_version = struct.pack("<HH", 1, 0)  # version 1.0
    else:
        iface_uuid_body = bytes(16)
        iface_version = struct.pack("<HH", 0, 0)

    # Build body
    body = struct.pack("<I", inquiry_type)  # inquiry_type
    body += object_uuid_body  # object UUID
    body += iface_uuid_body  # interface UUID
    body += iface_version  # interface version
    body += struct.pack("<I", 0)  # vers_option
    body += struct.pack("<I", 0)  # entry_handle (context for continuation)
    body += struct.pack("<I", 100)  # max_ents (max entries to return)

    # Update body length in header
    rpc_header = rpc_header[:74] + struct.pack("<H", len(body)) + rpc_header[76:]

    # Send request
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(rpc_header + body, (ip, port))

        # Receive response
        try:
            data, addr = sock.recvfrom(4096)
        except SocketTimeout:
            logger.debug(f"EPM lookup timeout for {ip}:{port}")
            return []

        if len(data) < 80:
            logger.debug(f"EPM response too short: {len(data)} bytes")
            return []

        # Parse RPC header
        resp_type = data[1]
        if resp_type == 0x03:  # FAULT
            logger.debug("EPM lookup returned FAULT")
            return []
        if resp_type != 0x02:  # Not RESPONSE
            logger.debug(f"Unexpected RPC response type: {resp_type}")
            return []

        body_len = struct.unpack("<H", data[74:76])[0]
        body_data = data[80 : 80 + body_len]

        if len(body_data) < 12:
            return []

        # Parse EPM response body
        offset = 0

        # entry_handle (context for continuation)
        # entry_handle = struct.unpack("<I", body_data[offset:offset+4])[0]
        offset += 4

        # num_ents (number of entries)
        num_ents = struct.unpack("<I", body_data[offset : offset + 4])[0]
        offset += 4

        # Skip array metadata (max_count, offset, actual_count)
        offset += 12

        endpoints = []

        for _ in range(num_ents):
            if offset + 4 > len(body_data):
                break

            # Entry object UUID
            if offset + 16 > len(body_data):
                break
            entry_object_uuid = _uuid_bytes_to_string(body_data[offset : offset + 16])
            offset += 16

            # Tower pointer (reference ID)
            if offset + 4 > len(body_data):
                break
            offset += 4  # tower_p (pointer/reference)

            # Annotation length
            if offset + 4 > len(body_data):
                break
            annotation_len = struct.unpack("<I", body_data[offset : offset + 4])[0]
            offset += 4

            # Extract annotation string (device model/article number)
            annotation = ""
            if annotation_len > 0 and offset + annotation_len <= len(body_data):
                annotation_bytes = body_data[offset : offset + annotation_len]
                # Remove null terminator and decode
                annotation = annotation_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
            offset += annotation_len
            # Align to 4 bytes
            offset = (offset + 3) & ~3

            # Tower length
            if offset + 4 > len(body_data):
                break
            tower_len = struct.unpack("<I", body_data[offset : offset + 4])[0]
            offset += 4

            # Tower data
            if offset + tower_len > len(body_data):
                break
            tower_data = body_data[offset : offset + tower_len]
            offset += tower_len
            # Align to 4 bytes
            offset = (offset + 3) & ~3

            # Parse tower
            endpoint = _parse_epm_tower(tower_data)
            if endpoint:
                endpoint.object_uuid = entry_object_uuid
                endpoint.annotation = annotation
                endpoints.append(endpoint)

        return endpoints

    finally:
        sock.close()


def get_station_info(
    sock: socket,
    src: bytes,
    name: str,
    timeout_sec: int = 10,
) -> dcp.DCPDeviceDescription:
    """Get device information by station name.

    Sends a DCP request filtered by station name and returns
    the device description.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        name: PROFINET station name
        timeout_sec: Discovery timeout in seconds

    Returns:
        DCPDeviceDescription for the device

    Raises:
        DCPDeviceNotFoundError: If device not found
    """
    dcp.send_request(sock, src, PNDCPBlock.NAME_OF_STATION, bytes(name, "utf-8"))
    responses = dcp.read_response(sock, src, timeout_sec=timeout_sec, once=True)

    if not responses:
        raise DCPDeviceNotFoundError(f"Device with name '{name}' not found")

    mac, blocks = list(responses.items())[0]
    return dcp.DCPDeviceDescription(mac, blocks)


class RPCCon:
    """PROFINET DCE/RPC connection to an IO-Device.

    This class implements an IO-Controller that can connect to
    PROFINET IO-Devices and perform read/write operations.

    Attributes:
        info: Device description from DCP discovery
        ar_uuid: Application Relationship UUID
        live: Timestamp of last communication (for timeout)

    Example:
        >>> info = get_station_info(sock, src_mac, "device-name")
        >>> with RPCCon(info) as conn:
        ...     conn.connect(src_mac)
        ...     data = conn.read(api=0, slot=0, subslot=1, idx=0xAFF0)
    """

    def __init__(
        self,
        info: dcp.DCPDeviceDescription,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize RPC connection to device.

        Args:
            info: Device description from DCP discovery
            timeout: Socket timeout in seconds
        """
        self.info = info
        self.timeout = timeout
        self.peer = (info.ip, RPC_PORT)

        # UUIDs for this connection (must be random per IEC 61158)
        self.ar_uuid = os.urandom(16)
        self.activity_uuid = os.urandom(16)

        # Object UUIDs (local and remote)
        self.local_object_uuid = PNRPCHeader.OBJECT_UUID_PREFIX + bytes(
            [0x00, 0x01, 0x76, 0x54, 0x32, 0x10]
        )
        self.remote_object_uuid = PNRPCHeader.OBJECT_UUID_PREFIX + bytes(
            [0x00, 0x01, info.device_high, info.device_low,
             info.vendor_high, info.vendor_low]
        )

        # Connection state
        self.live: Optional[datetime] = None
        self.src_mac: Optional[bytes] = None
        self.session_key: int = 1  # Session key for AR (default 1)

        # AlarmCR state
        self._alarm_ref: int = 1  # Controller's local alarm reference
        self._device_alarm_ref: int = 0  # Device's alarm reference (set after connect)
        self._alarm_cr_enabled: bool = False  # Whether AlarmCR was established

        # IOCR state
        self._iocr_ref_counter: int = 1  # Counter for IOCR references
        self._input_iocr_ref: int = 0  # Input IOCR reference
        self._output_iocr_ref: int = 0  # Output IOCR reference
        self._input_frame_id: int = 0  # Assigned input frame ID
        self._output_frame_id: int = 0  # Assigned output frame ID
        self._iocr_setup: Optional[IOCRSetup] = None  # IOCR config if enabled

        # UDP socket for RPC with timeout
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self._socket.settimeout(timeout)

    def _create_rpc(self, operation: int, nrd: bytes) -> PNRPCHeader:
        """Create RPC request packet."""
        return PNRPCHeader(
            0x04,  # Version
            PNRPCHeader.REQUEST,
            0x20,  # Flags1
            0x00,  # Flags2
            bytes([0x00, 0x00, 0x00]),  # DRep (big-endian, ASCII, IEEE float)
            0x00,  # Serial High
            self.remote_object_uuid,
            PNRPCHeader.IFACE_UUID_DEVICE,
            self.activity_uuid,
            0,  # ServerBootTime
            1,  # InterfaceVersion
            0,  # SequenceNumber
            operation,
            0xFFFF,  # InterfaceHint
            0xFFFF,  # ActivityHint
            len(nrd),
            0,  # FragmentNumber
            0,  # AuthenticationProtocol
            0,  # SerialLow
            payload=nrd,
        )

    def _create_nrd(self, payload: bytes) -> PNNRDData:
        """Create NRD (Network Representation Data) wrapper."""
        return PNNRDData(
            1500,  # args_maximum_status
            len(payload),  # args_length
            1500,  # maximum_count
            0,  # offset
            len(payload),  # actual_count
            payload=payload,
        )

    def _build_alarm_cr_block(
        self,
        transport: int = 0,
        priority: int = 0,
    ) -> bytes:
        """Build AlarmCRBlockReq (0x0103) for AR establishment.

        Per IEC 61158-6-10, the AlarmCR (Alarm Connection Relationship)
        enables asynchronous alarm notifications from device to controller.

        Args:
            transport: 0=Layer2 (RTA over Ethernet), 1=UDP
            priority: 0=low priority alarms, 1=high priority alarms

        Returns:
            Serialized AlarmCRBlockReq bytes
        """
        # AlarmCRProperties: bit 0=priority, bit 1=transport
        properties = (transport << 1) | priority

        # Block header: type 0x0103, length = total - 4 (excludes type+length)
        # AlarmCRBlockReq fixed size = 26 bytes, header contributes 6
        block_length = PNAlarmCRBlockReq.fmt_size - 4  # 22 bytes
        block = PNBlockHeader(
            PNAlarmCRBlockReq.BLOCK_TYPE,
            block_length,
            0x01,  # version high
            0x00,  # version low
        )

        alarm_cr = PNAlarmCRBlockReq(
            block_header=bytes(block),
            alarm_cr_type=0x0001,  # Standard AlarmCR
            lt=0x8892 if transport == 0 else 0x0800,  # EtherType or IP
            alarm_cr_properties=properties,
            rta_timeout_factor=PNAlarmCRBlockReq.DEFAULT_RTA_TIMEOUT_FACTOR,
            rta_retries=PNAlarmCRBlockReq.DEFAULT_RTA_RETRIES,
            local_alarm_reference=self._alarm_ref,
            max_alarm_data_length=PNAlarmCRBlockReq.DEFAULT_MAX_ALARM_DATA_LENGTH,
            alarm_cr_tag_header_high=PNAlarmCRBlockReq.DEFAULT_TAG_HEADER_HIGH,
            alarm_cr_tag_header_low=PNAlarmCRBlockReq.DEFAULT_TAG_HEADER_LOW,
        )

        return bytes(alarm_cr)

    def _parse_alarm_cr_response(self, response_data: bytes) -> int:
        """Parse AlarmCRBlockRes from connect response.

        Args:
            response_data: NRD payload containing response blocks

        Returns:
            Device's local alarm reference, or 0 if not found
        """
        # Scan for block type 0x8103 (AlarmCRBlockRes)
        offset = 0
        while offset + 6 <= len(response_data):
            block_type = unpack(">H", response_data[offset:offset + 2])[0]
            block_length = unpack(">H", response_data[offset + 2:offset + 4])[0]

            if block_type == PNAlarmCRBlockRes.BLOCK_TYPE:
                # Found AlarmCRBlockRes
                try:
                    alarm_res = PNAlarmCRBlockRes(response_data[offset:])
                    return alarm_res.local_alarm_reference
                except (ValueError, IndexError):
                    pass

            # Move to next block (block_length + 4 for header)
            offset += 4 + block_length
            # Align to 4 bytes
            offset = (offset + 3) & ~3

        return 0

    def _build_iocr_block(
        self,
        iocr_type: int,
        iocr_reference: int,
        setup: IOCRSetup,
    ) -> bytes:
        """Build IOCRBlockReq (0x0102) for AR establishment.

        Per IEC 61158-6-10, IOCRs define cyclic data exchange channels.
        Input IOCR: device -> controller
        Output IOCR: controller -> device

        Args:
            iocr_type: 1=Input, 2=Output
            iocr_reference: Local IOCR reference number
            setup: IOCRSetup with timing and slot configuration

        Returns:
            Serialized IOCRBlockReq bytes
        """
        # Calculate frame offset for each slot
        # Each IO object: data + IOPS byte
        objects_data = b""
        frame_offset = 0

        for slot in setup.slots:
            if iocr_type == 1:  # Input IOCR
                data_len = slot.input_length
            else:  # Output IOCR
                data_len = slot.output_length

            if data_len > 0:
                obj = IOCRAPIObject(
                    slot_number=slot.slot,
                    subslot_number=slot.subslot,
                    frame_offset=frame_offset,
                )
                objects_data += bytes(obj)
                frame_offset += data_len + 1  # data + IOPS

        # Pad to minimum 40 bytes
        data_length = max(40, frame_offset)

        # IOCR properties: RT_CLASS_1 = 0x01
        iocr_properties = 0x00000001  # RT_CLASS_1

        # Number of objects
        num_objects = len([s for s in setup.slots if
                          (iocr_type == 1 and s.input_length > 0) or
                          (iocr_type == 2 and s.output_length > 0)])

        # Build IOCRAPI per IEC 61158-6-10:
        # API(4) + nbr_io_data(2) + io_data[] + nbr_iocs(2) + iocs[]
        api_block = pack(">I", 0)  # API = 0
        api_block += pack(">H", num_objects)  # Number of IO data objects
        api_block += objects_data  # Frame descriptors for IO data
        # Add IOCS objects (consumer status - we don't typically need these)
        api_block += pack(">H", 0)  # Number of IOCS objects (none)

        # Calculate block length: header(38) + api_block
        header_size = PNIOCRBlockReqHeader.fmt_size
        total_size = header_size + len(api_block)
        block_length = total_size - 4  # Exclude type + length fields

        block = PNBlockHeader(
            PNIOCRBlockReqHeader.BLOCK_TYPE,
            block_length,
            0x01,  # version high
            0x00,  # version low
        )

        iocr_header = PNIOCRBlockReqHeader(
            block_header=bytes(block),
            iocr_type=iocr_type,
            iocr_reference=iocr_reference,
            lt=0x8892,  # PROFINET EtherType
            iocr_properties=iocr_properties,
            data_length=data_length,
            frame_id=0x8000 + iocr_reference,  # Placeholder, device assigns
            send_clock_factor=setup.send_clock_factor,
            reduction_ratio=setup.reduction_ratio,
            phase=0,
            sequence=0,
            frame_send_offset=0xFFFFFFFF,
            watchdog_factor=setup.watchdog_factor,
            data_hold_factor=setup.data_hold_factor,
            iocr_tag_header=0xC000,
            iocr_multicast_mac=bytes(6),
            number_of_apis=1,
        )

        return bytes(iocr_header) + api_block

    def _build_expected_submodule_block(
        self,
        setup: IOCRSetup,
    ) -> bytes:
        """Build ExpectedSubmoduleBlockReq (0x0104) for AR establishment.

        Tells the device what modules/submodules we expect.

        Args:
            setup: IOCRSetup with slot configuration

        Returns:
            Serialized ExpectedSubmoduleBlockReq bytes
        """
        builder = ExpectedSubmoduleBlockReq()

        for slot_cfg in setup.slots:
            builder.add_submodule(
                api=0,
                slot=slot_cfg.slot,
                subslot=slot_cfg.subslot,
                module_ident=slot_cfg.module_ident,
                submodule_ident=slot_cfg.submodule_ident,
                input_length=slot_cfg.input_length,
                output_length=slot_cfg.output_length,
            )

        return builder.to_bytes()

    def _parse_iocr_response(
        self,
        response_data: bytes,
        iocr_type: int,
    ) -> int:
        """Parse IOCRBlockRes from connect response.

        Args:
            response_data: NRD payload containing response blocks
            iocr_type: IOCR type to find (1=input, 2=output)

        Returns:
            Assigned frame ID, or 0 if not found
        """
        # Scan for block type 0x8102 (IOCRBlockRes)
        offset = 0
        while offset + 6 <= len(response_data):
            block_type = unpack(">H", response_data[offset:offset + 2])[0]
            block_length = unpack(">H", response_data[offset + 2:offset + 4])[0]

            if block_type == PNIOCRBlockRes.BLOCK_TYPE:
                try:
                    iocr_res = PNIOCRBlockRes(response_data[offset:])
                    if iocr_res.iocr_type == iocr_type:
                        return iocr_res.frame_id
                except (ValueError, IndexError):
                    pass

            # Move to next block
            offset += 4 + block_length
            offset = (offset + 3) & ~3  # Align to 4 bytes

        return 0

    def _send_receive(self, rpc: PNRPCHeader) -> PNRPCHeader:
        """Send RPC request and receive response with validation.

        Args:
            rpc: RPC request packet

        Returns:
            Parsed RPC response

        Raises:
            RPCTimeoutError: If no response received
            RPCFaultError: If device returned fault
            RPCError: If unexpected response type
        """
        self._socket.sendto(bytes(rpc), self.peer)

        try:
            data = self._socket.recvfrom(4096)[0]
        except SocketTimeout:
            raise RPCTimeoutError(
                f"No response from {self.info.name} ({self.info.ip})"
            ) from None
        except OSError as e:
            raise RPCError(f"Socket error: {e}") from e

        try:
            rpc_resp = PNRPCHeader(data)
        except ValueError as e:
            raise RPCError(f"Failed to parse RPC response: {e}") from e

        # Validate response type
        if rpc_resp.packet_type == PNRPCHeader.FAULT:
            raise RPCFaultError(
                f"RPC fault from {self.info.name}",
                fault_code=rpc_resp.operation_number,
            )
        elif rpc_resp.packet_type == PNRPCHeader.REJECT:
            raise RPCError(f"RPC request rejected by {self.info.name}")
        elif rpc_resp.packet_type != PNRPCHeader.RESPONSE:
            raise RPCError(
                f"Unexpected RPC packet type: 0x{rpc_resp.packet_type:02X}"
            )

        self.live = datetime.now()
        return rpc_resp

    def _check_timeout(self) -> None:
        """Check if connection has timed out and reconnect if needed."""
        if self.live is not None:
            elapsed = (datetime.now() - self.live).seconds
            if elapsed >= CONNECTION_TIMEOUT:
                logger.debug("Connection timeout, reconnecting...")
                self.connect()

    def connect(
        self,
        src_mac: Optional[bytes] = None,
        with_alarm_cr: bool = False,
        iocr_setup: Optional[IOCRSetup] = None,
    ) -> Optional[ConnectResult]:
        """Establish AR (Application Relationship) with device.

        Args:
            src_mac: Source MAC address (required for first connect)
            with_alarm_cr: Enable AlarmCR for async alarm notifications (default: False)
                          Note: Not all devices support AlarmCR. Enable only if your
                          device supports async alarm notifications.
            iocr_setup: Optional IOCR configuration for cyclic IO exchange.
                       If provided, Input/Output IOCRs are established along with
                       the AR. The device assigns frame IDs returned in ConnectResult.

        Returns:
            ConnectResult with frame IDs if iocr_setup provided, None otherwise

        Raises:
            ValueError: If src_mac not provided on first connect
            RPCConnectionError: If connection fails
        """
        if self.live is None:
            if src_mac is None:
                raise ValueError("src_mac required for initial connection")
            self.src_mac = src_mac
        elif src_mac is not None:
            self.src_mac = src_mac

        if self.src_mac is None:
            raise ValueError("No source MAC address available")

        # Store IOCR setup for later use
        self._iocr_setup = iocr_setup

        # Warn about experimental IOCR feature
        if iocr_setup:
            logger.warning(
                "IOCR/Cyclic IO is EXPERIMENTAL and NOT TESTED with real devices. "
                "Use at your own risk."
            )

        # Create AR block request
        block = PNBlockHeader(
            0x0101,  # ARBlockReq
            PNARBlockRequest.fmt_size - 2,
            0x01,
            0x00,
        )

        ar = PNARBlockRequest(
            bytes(block),
            0x0006,  # AR Type (IOCARSingle)
            self.ar_uuid,
            0x1234,  # Session key
            self.src_mac,
            self.local_object_uuid,
            0x0131,  # AR Properties (bits 0,4,5,8 set: supervisor-takeover, pull/plug allowed)
            100,  # Timeout factor
            0x8892,  # UDP RT port
            2,  # Station name length
            cm_initiator_station_name=bytes("tp", encoding="utf-8"),
            payload=b"",
        )

        # Build NRD payload with AR block
        nrd_payload = bytes(ar)

        # Add IOCR blocks if cyclic IO requested
        if iocr_setup:
            # Input IOCR: device -> controller
            self._input_iocr_ref = self._iocr_ref_counter
            self._iocr_ref_counter += 1
            input_iocr = self._build_iocr_block(
                iocr_type=1,  # Input
                iocr_reference=self._input_iocr_ref,
                setup=iocr_setup,
            )
            nrd_payload += input_iocr

            # Output IOCR: controller -> device
            self._output_iocr_ref = self._iocr_ref_counter
            self._iocr_ref_counter += 1
            output_iocr = self._build_iocr_block(
                iocr_type=2,  # Output
                iocr_reference=self._output_iocr_ref,
                setup=iocr_setup,
            )
            nrd_payload += output_iocr

            # ExpectedSubmoduleBlockReq tells device what modules we expect
            expected_submodule = self._build_expected_submodule_block(iocr_setup)
            nrd_payload += expected_submodule

        # Add AlarmCR block if requested
        if with_alarm_cr:
            alarm_cr_data = self._build_alarm_cr_block()
            nrd_payload += alarm_cr_data

        nrd = self._create_nrd(nrd_payload)
        rpc = self._create_rpc(PNRPCHeader.CONNECT, bytes(nrd))

        try:
            rpc_resp = self._send_receive(rpc)
            nrd_resp = PNNRDData(rpc_resp.payload)

            # Parse IOCR responses if cyclic IO enabled
            result = None
            if iocr_setup:
                result = ConnectResult(
                    ar_uuid=self.ar_uuid,
                    session_key=0x1234,
                )
                # Parse input IOCR response for frame ID
                self._input_frame_id = self._parse_iocr_response(nrd_resp.payload, 1)
                result.input_frame_id = self._input_frame_id
                if self._input_frame_id > 0:
                    logger.debug(f"Input IOCR frame ID: 0x{self._input_frame_id:04X}")

                # Parse output IOCR response for frame ID
                self._output_frame_id = self._parse_iocr_response(nrd_resp.payload, 2)
                result.output_frame_id = self._output_frame_id
                if self._output_frame_id > 0:
                    logger.debug(f"Output IOCR frame ID: 0x{self._output_frame_id:04X}")

            # Parse AlarmCR response if enabled
            if with_alarm_cr:
                self._device_alarm_ref = self._parse_alarm_cr_response(nrd_resp.payload)
                if self._device_alarm_ref > 0:
                    self._alarm_cr_enabled = True
                    logger.debug(f"AlarmCR established, device ref: {self._device_alarm_ref}")
                    if result:
                        result.device_alarm_ref = self._device_alarm_ref
                else:
                    logger.debug("AlarmCR not acknowledged by device")

            logger.info(f"Connected to {self.info.name} ({self.info.ip})")
            return result

        except RPCError as e:
            raise RPCConnectionError(f"Failed to connect: {e}") from e

    def read(
        self,
        api: int,
        slot: int,
        subslot: int,
        idx: int,
    ) -> PNIODHeader:
        """Read data from device via slot/subslot/index.

        Args:
            api: Application Process Identifier (usually 0)
            slot: Slot number
            subslot: Subslot number
            idx: Data record index

        Returns:
            PNIODHeader containing response payload

        Raises:
            RPCTimeoutError: If no response
            RPCError: If read fails
        """
        self._check_timeout()

        block = PNBlockHeader(PNBlockHeader.IODReadRequestHeader, 60, 0x01, 0x00)
        iod = PNIODHeader(
            bytes(block),
            0,  # sequence_number
            self.ar_uuid,
            api,
            slot,
            subslot,
            0,  # padding1
            idx,
            4096,  # length
            bytes(16),  # target_ar_uuid
            bytes(8),  # padding2
            payload=b"",
        )

        nrd = self._create_nrd(bytes(iod))
        rpc = self._create_rpc(PNRPCHeader.READ, bytes(nrd))

        rpc_resp = self._send_receive(rpc)
        nrd_resp = PNNRDData(rpc_resp.payload)

        # Check for PNIO errors in ArgsStatus field
        args_status = nrd_resp.args_maximum_status
        if args_status != 0:
            raise PNIOError.from_args_status(args_status)

        iod_resp = PNIODHeader(nrd_resp.payload)

        return iod_resp

    def read_implicit(
        self,
        api: int,
        slot: int,
        subslot: int,
        idx: int,
    ) -> PNIODHeader:
        """Read data without established AR (implicit read).

        Args:
            api: Application Process Identifier
            slot: Slot number
            subslot: Subslot number
            idx: Data record index

        Returns:
            PNIODHeader containing response payload
        """
        block = PNBlockHeader(PNBlockHeader.IODReadRequestHeader, 60, 0x01, 0x00)
        iod = PNIODHeader(
            bytes(block),
            0,
            bytes(16),  # Empty AR UUID for implicit
            api,
            slot,
            subslot,
            0,
            idx,
            4096,
            bytes(16),
            bytes(8),
            payload=b"",
        )

        nrd = self._create_nrd(bytes(iod))
        rpc = self._create_rpc(PNRPCHeader.IMPLICIT_READ, bytes(nrd))

        rpc_resp = self._send_receive(rpc)
        nrd_resp = PNNRDData(rpc_resp.payload)

        # Check for PNIO errors in ArgsStatus field
        args_status = nrd_resp.args_maximum_status
        if args_status != 0:
            raise PNIOError.from_args_status(args_status)

        iod_resp = PNIODHeader(nrd_resp.payload)

        return iod_resp

    def write(
        self,
        api: int,
        slot: int,
        subslot: int,
        idx: int,
        data: bytes,
    ) -> None:
        """Write data to device via slot/subslot/index.

        Args:
            api: Application Process Identifier
            slot: Slot number
            subslot: Subslot number
            idx: Data record index
            data: Data to write

        Raises:
            RPCTimeoutError: If no response
            RPCError: If write fails
        """
        self._check_timeout()

        block = PNBlockHeader(0x0008, 60, 0x01, 0x00)  # IODWriteReqHeader
        iod = PNIODHeader(
            bytes(block),
            0,
            self.ar_uuid,
            api,
            slot,
            subslot,
            0,
            idx,
            len(data),
            bytes(16),
            bytes(8),
            payload=bytes(data),
        )

        nrd = self._create_nrd(bytes(iod))
        rpc = self._create_rpc(PNRPCHeader.WRITE, bytes(nrd))

        rpc_resp = self._send_receive(rpc)
        nrd_resp = PNNRDData(rpc_resp.payload)

        # Check for PNIO errors in ArgsStatus field
        args_status = nrd_resp.args_maximum_status
        if args_status != 0:
            raise PNIOError.from_args_status(args_status)

        logger.debug(f"Write to slot={slot} subslot={subslot} idx=0x{idx:04X} OK")

    def write_multiple(
        self,
        writes: List[Tuple[int, int, int, bytes, int]],
    ) -> List[WriteMultipleResult]:
        """Write multiple records atomically using IODWriteMultipleReq (0xE040).

        All writes are sent in a single RPC request and processed atomically.
        This is more efficient than multiple single writes and ensures consistency.

        Args:
            writes: List of (slot, subslot, index, data, api) tuples.
                   Use api=0 for most cases.

        Returns:
            List of WriteMultipleResult, one per write request.

        Raises:
            RPCTimeoutError: If no response
            RPCError: If write operation fails

        Example:
            >>> results = conn.write_multiple([
            ...     (0, 1, 0xAFF1, b"Function\\x00" * 4, 0),  # I&M1
            ...     (0, 1, 0xAFF2, b"2024-01-15 10:30" + b"\\x00", 0),  # I&M2
            ... ])
            >>> for r in results:
            ...     print(f"Write to 0x{r.index:04X}: {'OK' if r.success else 'FAIL'}")
        """
        self._check_timeout()

        if not writes:
            return []

        # Build IODWriteMultipleReq using builder
        builder = IODWriteMultipleBuilder(self.ar_uuid, seq_num=0)
        for slot, subslot, index, data, api in writes:
            builder.add_write(slot, subslot, index, data, api)

        payload = builder.build()

        # Use write() infrastructure but with special index 0xE040
        block = PNBlockHeader(0x0008, 60, 0x01, 0x00)  # IODWriteReqHeader
        iod = PNIODHeader(
            bytes(block),
            0,
            self.ar_uuid,
            0xFFFFFFFF,  # API wildcard for multiple
            0xFFFF,  # Slot wildcard
            0xFFFF,  # Subslot wildcard
            0,
            IODWriteMultipleBuilder.INDEX,  # 0xE040
            len(payload),
            bytes(16),
            bytes(8),
            payload=payload,
        )

        nrd = self._create_nrd(bytes(iod))
        rpc = self._create_rpc(PNRPCHeader.WRITE, bytes(nrd))

        rpc_resp = self._send_receive(rpc)
        nrd_resp = PNNRDData(rpc_resp.payload)

        # Check for PNIO errors
        args_status = nrd_resp.args_maximum_status
        if args_status != 0:
            raise PNIOError.from_args_status(args_status)

        # Parse individual results
        results = parse_write_multiple_response(nrd_resp.payload)

        logger.debug(f"WriteMultiple: {len(results)} writes, "
                    f"{sum(1 for r in results if r.success)} succeeded")

        return results

    def read_module_diff(self) -> ModuleDiffBlock:
        """Read and parse ModuleDiffBlock (0xF830) from device.

        ModuleDiffBlock shows the comparison between expected and real
        module/submodule configuration. Useful for verifying that the
        device configuration matches expectations after Connect.

        Returns:
            ModuleDiffBlock with per-module/submodule state info

        Raises:
            RPCError: If read fails

        Example:
            >>> diff = conn.read_module_diff()
            >>> if diff.all_ok:
            ...     print("Configuration matches!")
            >>> else:
            ...     for slot, subslot, state in diff.get_mismatches():
            ...         print(f"Mismatch at slot={slot} subslot={subslot}: {state}")
        """
        iod = self.read(api=0, slot=0, subslot=0, idx=indices.MODULE_DIFF_BLOCK)
        return parse_module_diff_block(iod.payload)

    def read_inm0filter(self) -> Dict[int, Dict[int, Tuple[int, Dict[int, int]]]]:
        """Read IM0 filter data (module/submodule enumeration).

        Returns device topology as nested dictionaries:
        {api: {slot: (module_id, {subslot: submodule_id})}}

        Returns:
            Nested dictionary of API -> Slot -> (Module, Subslots)
        """
        # Read PDRealData at index 0xF840
        iod = self.read(api=0, slot=0, subslot=0, idx=0xF840)
        data = iod.payload

        # Skip block header
        PNBlockHeader(data)  # validate block header
        data = data[6:]

        result: Dict[int, Dict[int, Tuple[int, Dict[int, int]]]] = {}

        # Parse API count
        num_api = unpack(">H", data[:2])[0]
        data = data[2:]

        for _ in range(num_api):
            # Parse API header
            api, num_modules = unpack(">IH", data[:6])
            data = data[6:]
            result[api] = {}

            for _ in range(num_modules):
                # Parse module header
                slot_number, module_ident_num, num_subslots = unpack(">HIH", data[:8])
                data = data[8:]

                subslots: Dict[int, int] = {}
                for _ in range(num_subslots):
                    # Parse subslot entry
                    subslot_number, submodule_ident_number = unpack(">HI", data[:6])
                    data = data[6:]
                    subslots[subslot_number] = submodule_ident_number

                result[api][slot_number] = (module_ident_num, subslots)

        return result

    def read_im0(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM0:
        """Read I&M0 identification data from device.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM0 structure with device identification
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM0.IDX)
        return PNInM0(iod.payload)

    def read_im1(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM1:
        """Read I&M1 tag function/location data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM1 structure with tag function and location
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM1.IDX)
        return PNInM1(iod.payload)

    def read_im2(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM2:
        """Read I&M2 installation date data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM2 structure with installation date (YYYY-MM-DD HH:MM format)
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM2.IDX)
        return PNInM2(iod.payload)

    def read_im3(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM3:
        """Read I&M3 descriptor data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM3 structure with general descriptor (54 bytes)
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM3.IDX)
        return PNInM3(iod.payload)

    def read_im4(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM4:
        """Read I&M4 PROFIsafe signature data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM4 structure with PROFIsafe signature (54 bytes, binary)
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM4.IDX)
        return PNInM4(iod.payload)

    def read_im5(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM5:
        """Read I&M5 annotation data.

        Note: I&M5 is optional and may not be supported by all devices.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM5 structure with annotation string (64 bytes)
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM5.IDX)
        return PNInM5(iod.payload)

    def read_im6(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM6:
        """Read I&M6 data (reserved for future use).

        Note: I&M6 is reserved and may not be supported by devices.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM6 structure with raw payload
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM6.IDX)
        return PNInM6(iod.payload)

    def read_im7(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM7:
        """Read I&M7 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM7.IDX)
        return PNInM7(iod.payload)

    def read_im8(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM8:
        """Read I&M8 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM8.IDX)
        return PNInM8(iod.payload)

    def read_im9(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM9:
        """Read I&M9 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM9.IDX)
        return PNInM9(iod.payload)

    def read_im10(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM10:
        """Read I&M10 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM10.IDX)
        return PNInM10(iod.payload)

    def read_im11(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM11:
        """Read I&M11 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM11.IDX)
        return PNInM11(iod.payload)

    def read_im12(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM12:
        """Read I&M12 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM12.IDX)
        return PNInM12(iod.payload)

    def read_im13(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM13:
        """Read I&M13 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM13.IDX)
        return PNInM13(iod.payload)

    def read_im14(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM14:
        """Read I&M14 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM14.IDX)
        return PNInM14(iod.payload)

    def read_im15(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PNInM15:
        """Read I&M15 data (reserved for future use)."""
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=PNInM15.IDX)
        return PNInM15(iod.payload)

    def read_all_im(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> Dict[str, Any]:
        """Read all available I&M records from device.

        Attempts to read I&M0-15 records, returning only those supported.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            Dictionary with available I&M records
        """
        result: Dict[str, Any] = {}

        # I&M0 is mandatory
        try:
            result["im0"] = self.read_im0(slot, subslot)
        except RPCError as e:
            logger.warning(f"Failed to read I&M0: {e}")

        # I&M1 is optional
        try:
            result["im1"] = self.read_im1(slot, subslot)
        except RPCError:
            logger.debug("I&M1 not supported")

        # I&M2-15 are optional (I&M6-15 are reserved for future use)
        optional_im = [
            ("im2", self.read_im2),
            ("im3", self.read_im3),
            ("im4", self.read_im4),
            ("im5", self.read_im5),
            ("im6", self.read_im6),
            ("im7", self.read_im7),
            ("im8", self.read_im8),
            ("im9", self.read_im9),
            ("im10", self.read_im10),
            ("im11", self.read_im11),
            ("im12", self.read_im12),
            ("im13", self.read_im13),
            ("im14", self.read_im14),
            ("im15", self.read_im15),
        ]
        for idx, (name, reader) in enumerate(optional_im, start=2):
            try:
                result[name] = reader(slot, subslot)
            except (RPCError, ValueError):
                logger.debug(f"I&M{idx} not supported")

        return result

    # =========================================================================
    # Port & Interface Records
    # =========================================================================

    def read_port_statistics(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PortStatistics:
        """Read port statistics (record 0x8028).

        Args:
            slot: Slot number
            subslot: Subslot number (port)

        Returns:
            PortStatistics with counters
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=0x8028)
        data = iod.payload
        stats = PortStatistics()

        # Skip block header (6 bytes)
        if len(data) >= 10:
            # Parse counters (format varies by device)
            pass  # Basic structure returned

        return stats

    def read_link_data(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> LinkData:
        """Read port link data (record 0x8029).

        Args:
            slot: Slot number
            subslot: Subslot number (port)

        Returns:
            LinkData with link state and speed
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=0x8029)
        data = iod.payload
        link = LinkData()

        if len(data) >= 12:
            # Skip block header (6 bytes)
            # Parse link state and MAU type
            link.mau_type = unpack(">H", data[8:10])[0] if len(data) >= 10 else 0
            link.mau_type_name = MAU_TYPES.get(link.mau_type, f"Unknown ({link.mau_type})")

        return link

    def read_interface_info(self) -> InterfaceInfo:
        """Read interface information (PDInterfaceDataReal 0x8080).

        Returns:
            InterfaceInfo with MAC, IP, chassis ID
        """
        iod = self.read(api=0, slot=0, subslot=0, idx=0x8080)
        data = iod.payload
        info = InterfaceInfo()

        if len(data) > 10:
            # Skip block header (6 bytes), then padding (2 bytes)
            offset = 6
            if offset < len(data):
                chassis_len = data[offset]
                offset += 1
                if offset + chassis_len <= len(data):
                    info.chassis_id = data[offset:offset + chassis_len].decode("utf-8", errors="replace")
                    offset += chassis_len
                    # Align to 2 bytes
                    if (1 + chassis_len) % 2:
                        offset += 1

                    # MAC address (6 bytes)
                    if offset + 6 <= len(data):
                        mac = data[offset:offset + 6]
                        info.mac = ":".join(f"{b:02x}" for b in mac)
                        offset += 6 + 2  # MAC + padding

                    # IP, netmask, gateway (4 bytes each)
                    if offset + 12 <= len(data):
                        info.ip = ".".join(str(b) for b in data[offset:offset + 4])
                        info.netmask = ".".join(str(b) for b in data[offset + 4:offset + 8])
                        info.gateway = ".".join(str(b) for b in data[offset + 8:offset + 12])

        return info

    def read_port_info(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> PortInfo:
        """Read port information (PDPortDataReal 0x802A).

        Args:
            slot: Slot number
            subslot: Subslot/port number

        Returns:
            PortInfo with port details and peer info
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=0x802A)
        data = iod.payload
        info = PortInfo(slot=slot, subslot=subslot)

        if len(data) > 12:
            # Skip block header (6 bytes) + padding (2)
            offset = 8
            # Slot/subslot
            if offset + 4 <= len(data):
                info.slot = unpack(">H", data[offset:offset + 2])[0]
                info.subslot = unpack(">H", data[offset + 2:offset + 4])[0]
                offset += 4

            # Port ID length + string
            if offset < len(data):
                port_id_len = data[offset]
                offset += 1
                if offset + port_id_len <= len(data):
                    info.port_id = data[offset:offset + port_id_len].decode("utf-8", errors="replace")

        return info

    def read_topology(self) -> Tuple[InterfaceInfo, List[PortInfo]]:
        """Read full network topology (PDRealData 0xF841).

        Returns:
            Tuple of (interface_info, list of port_info)
        """
        iod = self.read(api=0, slot=0, subslot=0, idx=0xF841)
        data = iod.payload

        interface = InterfaceInfo()
        ports: List[PortInfo] = []

        def parse_block(block_data: bytes, offset: int) -> Optional[Tuple[int, int, bytes]]:
            """Parse a single block, return (type, len, content) or None."""
            if offset + 4 > len(block_data):
                return None
            block_type = unpack(">H", block_data[offset:offset + 2])[0]
            block_len = unpack(">H", block_data[offset + 2:offset + 4])[0]
            if block_type == 0 and block_len == 0:
                return None
            # Content after header (4) + version (2) = 6 bytes
            content = block_data[offset + 6:offset + 4 + block_len]
            return block_type, block_len, content

        def scan_for_blocks(block_data: bytes) -> None:
            """Scan data for known block types."""
            nonlocal interface, ports

            # Scan through data looking for known block signatures
            for i in range(0, len(block_data) - 6, 2):
                if i + 4 > len(block_data):
                    break

                block_type = unpack(">H", block_data[i:i + 2])[0]
                block_len = unpack(">H", block_data[i + 2:i + 4])[0]

                # Sanity checks
                if block_len == 0 or block_len > 500 or i + 4 + block_len > len(block_data):
                    continue

                content = block_data[i + 6:i + 4 + block_len]

                if block_type == 0x0240:  # PDInterfaceDataReal
                    if len(content) > 3:
                        chassis_len = content[0]
                        if chassis_len > 0 and chassis_len < 50:
                            interface.chassis_id = content[1:1 + chassis_len].decode("utf-8", errors="replace")

                            mac_offset = 1 + chassis_len
                            if mac_offset % 2:
                                mac_offset += 1
                            # Skip padding (2 bytes after name)
                            mac_offset += 2
                            if mac_offset + 6 <= len(content):
                                mac = content[mac_offset:mac_offset + 6]
                                interface.mac = ":".join(f"{b:02x}" for b in mac)

                            ip_offset = mac_offset + 6 + 2  # MAC + padding
                            if ip_offset + 12 <= len(content):
                                interface.ip = ".".join(str(b) for b in content[ip_offset:ip_offset + 4])
                                interface.netmask = ".".join(str(b) for b in content[ip_offset + 4:ip_offset + 8])
                                interface.gateway = ".".join(str(b) for b in content[ip_offset + 8:ip_offset + 12])

                elif block_type == 0x020F:  # PDPortDataReal
                    port = PortInfo()
                    if len(content) >= 10:
                        # Skip padding (2), then slot/subslot
                        port.slot = unpack(">H", content[2:4])[0]
                        port.subslot = unpack(">H", content[4:6])[0]
                        port_id_len = content[6]
                        if 7 + port_id_len <= len(content) and port_id_len > 0:
                            port.port_id = content[7:7 + port_id_len].decode("utf-8", errors="replace")
                            # Check if this port was already added
                            if not any(p.slot == port.slot and p.subslot == port.subslot for p in ports):
                                ports.append(port)

        scan_for_blocks(data)
        return interface, ports

    # =========================================================================
    # Diagnostic Records
    # =========================================================================

    def read_diagnosis(
        self,
        slot: int = 0,
        subslot: int = 0,
        index: int = 0xF000,
    ) -> DiagnosisData:
        """Read and parse diagnosis data.

        Args:
            slot: Slot number
            subslot: Subslot number
            index: Diagnosis record index (default: 0xF000 for all diagnosis)
                   Other options:
                   - 0x800A: Channel diagnosis for slot
                   - 0x800B: All diagnosis for slot
                   - 0x800C: Channel diagnosis for subslot
                   - 0xF00A: Channel diagnosis for API
                   - 0xF00B: All diagnosis for API

        Returns:
            DiagnosisData with parsed diagnosis entries

        Example:
            >>> diag = rpc.read_diagnosis()
            >>> for entry in diag.entries:
            ...     print(f"Channel {entry.channel_number}: {entry.error_type_name}")
        """
        try:
            iod = self.read(api=0, slot=slot, subslot=subslot, idx=index)
            data = iod.payload

            if len(data) > 6:
                # Try full parsing first
                result = parse_diagnosis_block(data, api=0, slot=slot, subslot=subslot)

                # If no entries found, try simpler parsing
                if not result.entries:
                    result = parse_diagnosis_simple(data, api=0, slot=slot, subslot=subslot)

                return result
            else:
                return DiagnosisData(api=0, slot=slot, subslot=subslot, raw_data=data)

        except RPCError as e:
            logger.debug(f"Failed to read diagnosis index 0x{index:04X}: {e}")
            return DiagnosisData(api=0, slot=slot, subslot=subslot)

    def read_all_diagnosis(self) -> Dict[int, DiagnosisData]:
        """Read diagnosis from all standard indices.

        Returns:
            Dictionary mapping index to DiagnosisData
        """
        DIAGNOSIS_INDICES = [
            (0x800A, 0, 0, 0),      # Channel diagnosis for slot 0
            (0x800B, 0, 0, 0),      # All diagnosis for slot 0
            (0x800C, 0, 0, 1),      # Channel diagnosis for subslot 1
            (0xF000, 0, 0, 0),      # All diagnosis data (device level)
            (0xF00A, 0, 0, 0),      # Channel diagnosis (API level)
            (0xF00B, 0, 0, 0),      # All diagnosis (API level)
        ]

        results: Dict[int, DiagnosisData] = {}
        for idx, _api, slot, subslot in DIAGNOSIS_INDICES:
            try:
                diag = self.read_diagnosis(slot=slot, subslot=subslot, index=idx)
                if diag.entries:
                    results[idx] = diag
            except RPCError:
                pass

        return results

    def read_logbook(self) -> List[LogEntry]:
        """Read device log book (record 0xF830).

        Returns:
            List of LogEntry objects
        """
        entries: List[LogEntry] = []

        try:
            iod = self.read(api=0, slot=0, subslot=0, idx=0xF830)
            data = iod.payload

            if len(data) > 6:
                # Skip block header
                offset = 6
                # Parse log entries (structure: timestamp + detail)
                entry_count = 0
                while offset + 8 <= len(data) and entry_count < 50:
                    timestamp = unpack(">I", data[offset:offset + 4])[0]
                    detail = unpack(">I", data[offset + 4:offset + 8])[0]
                    if timestamp > 0 or detail > 0:
                        entries.append(LogEntry(timestamp=timestamp, entry_detail=detail))
                    offset += 8
                    entry_count += 1
        except RPCError:
            pass

        return entries

    def read_ar_info(self) -> Optional[ARInfo]:
        """Read Application Relationship info (record 0xF820).

        Returns:
            ARInfo or None if not available
        """
        try:
            iod = self.read(api=0, slot=0, subslot=0, idx=0xF820)
            data = iod.payload

            if len(data) >= 24:
                ar = ARInfo()
                # Skip block header (6 bytes)
                offset = 6
                # AR UUID (16 bytes)
                ar_uuid = data[offset + 2:offset + 18]
                ar.ar_uuid = ":".join(f"{b:02x}" for b in ar_uuid)
                offset += 18
                # AR type
                if offset + 2 <= len(data):
                    ar.ar_type = unpack(">H", data[offset:offset + 2])[0]
                return ar
        except RPCError:
            pass

        return None

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def enumerate_records(self) -> Dict[int, int]:
        """Scan and enumerate all available records.

        Returns:
            Dictionary of {record_index: size_in_bytes}
        """
        SCAN_INDICES = [
            # I&M
            0xAFF0, 0xAFF1, 0xAFF2, 0xAFF3, 0xAFF4, 0xAFF5,
            # Port/Interface
            0x8020, 0x8028, 0x8029, 0x802A, 0x802B, 0x802F,
            0x8050, 0x8051, 0x8080, 0x8090,
            # Diagnosis
            0x800A, 0x800B, 0x800C, 0x8010, 0x8011, 0x8012,
            # Device level
            0xF000, 0xF00A, 0xF00B, 0xF80C,
            # Real data
            0xF820, 0xF821, 0xF830, 0xF840, 0xF841, 0xF842, 0xF880,
            # Manufacturer (sample range)
            0xE000, 0xE001, 0xE002, 0xE010,
        ]

        found: Dict[int, int] = {}
        slots = [(0, 0, 0), (0, 0, 1), (0, 1, 1)]

        for idx in SCAN_INDICES:
            for api, slot, subslot in slots:
                try:
                    iod = self.read(api=api, slot=slot, subslot=subslot, idx=idx)
                    if iod.payload and len(iod.payload) > 0:
                        found[idx] = len(iod.payload)
                        break
                except (RPCError, ValueError):
                    pass

        return found

    def enumerate_indices(
        self,
        slot: int = 0,
        subslot: int = 1,
        indices: Optional[List[int]] = None,
        include_standard: bool = True,
        include_im: bool = True,
        include_diagnosis: bool = True,
        include_port: bool = True,
        verbose: bool = False,
    ) -> Dict[int, Dict[str, Any]]:
        """Enumerate available record indices on the device.

        Probes indices and reports which are readable, which return errors,
        and which return empty data.

        Args:
            slot: Slot number to probe
            subslot: Subslot number to probe
            indices: Custom list of indices to probe (overrides flags if provided)
            include_standard: Include standard device indices
            include_im: Include I&M indices
            include_diagnosis: Include diagnosis indices
            include_port: Include port/interface indices
            verbose: Log progress during enumeration

        Returns:
            Dictionary mapping index to result:
            {
                0xAFF0: {"status": "readable", "size": 60, "name": "I&M0"},
                0xAFF4: {"status": "error", "error": "Invalid index", "name": "I&M4"},
                0xFFFF: {"status": "empty", "name": "Unknown"},
            }
        """
        from . import indices as idx_module

        results: Dict[int, Dict[str, Any]] = {}

        # Build list of indices to probe
        if indices is not None:
            probe_list = [(i, idx_module.get_index_name(i)) for i in indices]
        else:
            probe_list = []
            if include_im:
                probe_list.extend(idx_module.IM_INDICES)
            if include_diagnosis:
                probe_list.extend(idx_module.DIAGNOSIS_INDICES["subslot"])
                probe_list.extend(idx_module.DIAGNOSIS_INDICES["device"])
            if include_port:
                probe_list.extend(idx_module.PORT_INDICES)
                probe_list.extend(idx_module.INTERFACE_INDICES)
            if include_standard:
                probe_list.extend(idx_module.DEVICE_INDICES)
                probe_list.extend([
                    (idx_module.EXPECTED_ID_SUBSLOT, "ExpectedIdentificationData"),
                    (idx_module.REAL_ID_SUBSLOT, "RealIdentificationData"),
                    (idx_module.MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
                    (idx_module.RECORD_INPUT_DATA, "RecordInputData"),
                    (idx_module.RECORD_OUTPUT_DATA, "RecordOutputData"),
                ])

        # Remove duplicates while preserving order
        seen = set()
        unique_list = []
        for idx, name in probe_list:
            if idx not in seen:
                seen.add(idx)
                unique_list.append((idx, name))

        # Probe each index
        for idx, name in unique_list:
            if verbose:
                logger.info(f"Probing index 0x{idx:04X} ({name})...")

            try:
                result = self.read(api=0, slot=slot, subslot=subslot, idx=idx)
                if len(result.payload) > 0:
                    results[idx] = {
                        "status": "readable",
                        "size": len(result.payload),
                        "name": name,
                    }
                else:
                    results[idx] = {
                        "status": "empty",
                        "name": name,
                    }
            except PNIOError as e:
                results[idx] = {
                    "status": "error",
                    "error": str(e.args[0]),
                    "error_code1": e.error_code1,
                    "error_code2": e.error_code2,
                    "name": name,
                }
            except RPCError as e:
                results[idx] = {
                    "status": "error",
                    "error": str(e),
                    "name": name,
                }

        return results

    def scan_slots(
        self,
        max_slot: int = 16,
        subslots: Optional[List[int]] = None,
    ) -> Dict[Tuple[int, int], Dict[str, Any]]:
        """Discover which slots and subslots have I&M0 data by scanning.

        Args:
            max_slot: Maximum slot number to scan
            subslots: Subslots to check (default: 0x0001, 0x8000, 0x8001, 0x8002)

        Returns:
            Dictionary mapping (slot, subslot) to info:
            {
                (0, 1): {"im0_size": 60, "type": "DAP"},
                (0, 0x8000): {"im0_size": 60, "type": "Interface"},
                (0, 0x8001): {"im0_size": 60, "type": "Port1"},
            }
        """
        from . import indices as idx_module

        if subslots is None:
            subslots = [
                idx_module.SUBSLOT_DAP,
                idx_module.SUBSLOT_INTERFACE,
                idx_module.SUBSLOT_PORT1,
                idx_module.SUBSLOT_PORT2,
            ]

        results: Dict[Tuple[int, int], Dict[str, Any]] = {}

        for slot in range(max_slot):
            for subslot in subslots:
                try:
                    result = self.read(api=0, slot=slot, subslot=subslot, idx=idx_module.IM0)
                    if len(result.payload) > 0:
                        # Determine subslot type
                        if subslot == idx_module.SUBSLOT_DAP:
                            subslot_type = "DAP"
                        elif subslot == idx_module.SUBSLOT_INTERFACE:
                            subslot_type = "Interface"
                        elif subslot >= idx_module.SUBSLOT_PORT1:
                            subslot_type = f"Port{subslot - idx_module.SUBSLOT_PORT1 + 1}"
                        else:
                            subslot_type = "Module"

                        results[(slot, subslot)] = {
                            "im0_size": len(result.payload),
                            "type": subslot_type,
                        }
                except (PNIOError, RPCError):
                    pass

        return results

    def read_raw(
        self,
        idx: int,
        slot: int = 0,
        subslot: int = 1,
    ) -> bytes:
        """Read raw record data by index.

        Args:
            idx: Record index
            slot: Slot number
            subslot: Subslot number

        Returns:
            Raw record payload bytes
        """
        iod = self.read(api=0, slot=slot, subslot=subslot, idx=idx)
        return iod.payload

    def read_pd_real_data(self) -> blocks.PDRealData:
        """Read and parse PDRealData (0xF841) from device.

        PDRealData contains the physical device structure including
        interface information and port details.

        Returns:
            PDRealData with parsed slots, interface, and ports

        Raises:
            RPCError: If read fails
        """
        iod = self.read(api=0, slot=0, subslot=1, idx=indices.PD_REAL_DATA)
        return blocks.parse_pd_real_data(iod.payload)

    def read_real_identification_data(self) -> blocks.RealIdentificationData:
        """Read and parse RealIdentificationData (0xF000) from device.

        RealIdentificationData contains the complete logical slot/subslot
        structure with module/submodule identification numbers.

        Returns:
            RealIdentificationData with parsed slot structure

        Raises:
            RPCError: If read fails
        """
        iod = self.read(api=0, slot=0, subslot=1, idx=indices.REAL_ID_API)
        return blocks.parse_real_identification_data(iod.payload)

    def discover_slots(self) -> List[blocks.SlotInfo]:
        """Discover all slots/subslots from device.

        Reads RealIdentificationData (0xF000) which provides the complete
        logical structure of the device including all APIs, slots, and subslots.

        Returns:
            List of SlotInfo for each discovered slot/subslot

        Raises:
            RPCError: If read fails
        """
        real_id = self.read_real_identification_data()
        return real_id.slots

    def discover_topology(self) -> Tuple[blocks.PDRealData, blocks.RealIdentificationData]:
        """Discover complete device topology.

        Reads both PDRealData (0xF841) for physical structure and
        RealIdentificationData (0xF000) for logical structure.

        Returns:
            Tuple of (PDRealData, RealIdentificationData)

        Raises:
            RPCError: If reads fail
        """
        pd_real = self.read_pd_real_data()
        real_id = self.read_real_identification_data()
        return pd_real, real_id

    # =========================================================================
    # CONTROL Operation (0x04)
    # =========================================================================

    def _send_control(
        self,
        block_type: int,
        control_command: int,
        wait_response: bool = True,
    ) -> Optional[bytes]:
        """Send a CONTROL operation request.

        Per IEC 61158-6-10, CONTROL is used for AR lifecycle state transitions.

        Args:
            block_type: Block type (e.g., 0x0110 for PrmEnd, 0x0112 for AppReady)
            control_command: Control command value
            wait_response: Whether to wait for response

        Returns:
            Response payload if wait_response=True, else None

        Raises:
            RPCError: If control fails and wait_response=True
        """
        if not self.live:
            raise RPCError("Not connected")

        # Build control block (same structure as release block)
        block = PNBlockHeader(block_type, 28, 0x01, 0x00)

        control_block = PNIODReleaseBlock(
            block_header=bytes(block),
            padding1=0,
            ar_uuid=self.ar_uuid,
            session_key=self.session_key,
            padding2=0,
            control_command=control_command,
            control_block_properties=0,
            payload=b"",
        )

        nrd = self._create_nrd(bytes(control_block))
        rpc = self._create_rpc(PNRPCHeader.CONTROL, bytes(nrd))

        if not wait_response:
            self._socket.sendto(bytes(rpc), self.peer)
            logger.debug(f"Sent control 0x{control_command:04X} to {self.info.name}")
            return None

        response = self._send_receive(rpc)
        return response

    def prm_begin(self) -> bytes:
        """Send PrmBegin control command.

        Starts the parameter phase for AR configuration.
        Should be called after CONNECT before writing parameters.

        Returns:
            Response payload

        Raises:
            RPCError: If control fails
        """
        from .indices import BLOCK_PRM_BEGIN_REQ, CONTROL_CMD_PRM_BEGIN

        return self._send_control(BLOCK_PRM_BEGIN_REQ, CONTROL_CMD_PRM_BEGIN)

    def prm_end(self) -> bytes:
        """Send PrmEnd control command.

        Ends the parameter phase after configuration is complete.
        Should be called after all parameters are written.

        Returns:
            Response payload

        Raises:
            RPCError: If control fails
        """
        from .indices import BLOCK_IOD_CONTROL_PRM_END_REQ, CONTROL_CMD_PRM_END

        return self._send_control(BLOCK_IOD_CONTROL_PRM_END_REQ, CONTROL_CMD_PRM_END)

    def application_ready(self) -> bytes:
        """Send ApplicationReady control command.

        Signals that the application is ready for cyclic data exchange.
        Should be called after PrmEnd.

        Returns:
            Response payload

        Raises:
            RPCError: If control fails
        """
        from .indices import BLOCK_IOD_CONTROL_APP_READY_REQ, CONTROL_CMD_APPLICATION_READY

        return self._send_control(
            BLOCK_IOD_CONTROL_APP_READY_REQ, CONTROL_CMD_APPLICATION_READY
        )

    def ready_for_rt_class_3(self) -> bytes:
        """Send ReadyForRT_CLASS_3 control command.

        Signals readiness for isochronous real-time data exchange.
        Only relevant for RT_CLASS_3 (IRT) ARs.

        Returns:
            Response payload

        Raises:
            RPCError: If control fails
        """
        from .indices import BLOCK_IOD_CONTROL_RT_CLASS_3_REQ, CONTROL_CMD_READY_FOR_RT_CLASS_3

        return self._send_control(
            BLOCK_IOD_CONTROL_RT_CLASS_3_REQ, CONTROL_CMD_READY_FOR_RT_CLASS_3
        )

    def disconnect(self) -> None:
        """Send Release request to properly terminate the AR.

        Per IEC 61158-6-10, sends ReleaseBlockReq (0x0114) with
        control command 0x0004 to terminate the application relation.
        """
        if not self.live:
            return  # Not connected

        try:
            # Build ReleaseBlockReq (block type 0x0114)
            block = PNBlockHeader(0x0114, 28, 0x01, 0x00)  # ReleaseBlockReq

            release = PNIODReleaseBlock(
                block_header=bytes(block),
                padding1=0,
                ar_uuid=self.ar_uuid,
                session_key=self.session_key,
                padding2=0,
                control_command=0x0004,  # Terminate AR
                control_block_properties=0,
                payload=b"",  # No payload for release
            )

            nrd = self._create_nrd(bytes(release))
            rpc = self._create_rpc(PNRPCHeader.RELEASE, bytes(nrd))

            # Send release, don't wait for response (best effort)
            self._socket.sendto(bytes(rpc), self.peer)
            logger.debug(f"Sent Release to {self.info.name}")

        except Exception as e:
            logger.debug(f"Release failed: {e}")

        self.live = None

    def close(self) -> None:
        """Close RPC connection (sends Release if connected)."""
        self.disconnect()
        try:
            self._socket.close()
        except OSError:
            pass
        logger.debug(f"Closed connection to {self.info.name}")

    def __enter__(self) -> RPCCon:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
