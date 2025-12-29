"""
Utility functions for PROFINET packet handling.

Provides:
- MAC/IP address conversion utilities
- Socket creation helpers
- Packet structure factory (make_packet)
- Timeout context manager

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import OrderedDict, namedtuple
from fcntl import ioctl
from socket import AF_INET, AF_PACKET, SOCK_DGRAM, SOCK_RAW, htons, socket
from struct import calcsize, pack, unpack
from typing import Any, Callable, Dict, Optional, Tuple, Type, Union

from .exceptions import InvalidIPError, InvalidMACError, PermissionDeniedError, SocketError

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# Network constants
MAX_ETHERNET_FRAME = 1522
PROFINET_ETHERTYPE = 0x8892
VLAN_ETHERTYPE = 0x8100
ETH_P_ALL = 0x0003  # Receive all Ethernet protocols

# ioctl constants (Linux-specific)
SIOCGIFHWADDR = 0x8927

# Validation patterns
MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# =============================================================================
# Address Conversion Utilities
# =============================================================================


def to_hex(data: bytes) -> str:
    """Convert bytes to colon-separated hex string."""
    return ":".join(f"{c:02x}" for c in data)


def s2mac(mac_str: str) -> bytes:
    """Convert MAC address string to bytes.

    Args:
        mac_str: MAC address in format "aa:bb:cc:dd:ee:ff"

    Returns:
        6-byte MAC address

    Raises:
        InvalidMACError: If MAC address format is invalid
    """
    if not mac_str:
        raise InvalidMACError("MAC address cannot be empty")

    if not MAC_PATTERN.match(mac_str):
        raise InvalidMACError(
            f"Invalid MAC address format: {mac_str!r}. "
            "Expected format: aa:bb:cc:dd:ee:ff"
        )

    try:
        result = bytes(int(num, 16) for num in mac_str.split(":"))
        if len(result) != 6:
            raise InvalidMACError(f"MAC address must be 6 bytes, got {len(result)}")
        return result
    except ValueError as e:
        raise InvalidMACError(f"Invalid MAC address: {mac_str!r}") from e


def mac2s(mac_bytes: bytes) -> str:
    """Convert MAC address bytes to string.

    Args:
        mac_bytes: 6-byte MAC address

    Returns:
        MAC address in format "aa:bb:cc:dd:ee:ff"

    Raises:
        InvalidMACError: If input is not 6 bytes
    """
    if len(mac_bytes) != 6:
        raise InvalidMACError(f"MAC address must be 6 bytes, got {len(mac_bytes)}")
    return ":".join(f"{num:02x}" for num in mac_bytes)


def s2ip(ip_bytes: bytes) -> str:
    """Convert IP address bytes to dotted decimal string.

    Args:
        ip_bytes: 4-byte IP address

    Returns:
        IP address in format "192.168.1.1"

    Raises:
        InvalidIPError: If input is not 4 bytes
    """
    if len(ip_bytes) < 4:
        raise InvalidIPError(f"IP address must be at least 4 bytes, got {len(ip_bytes)}")
    return ".".join(str(o) for o in ip_bytes[:4])


def ip2s(ip_str: str) -> bytes:
    """Convert dotted decimal IP string to bytes.

    Args:
        ip_str: IP address in format "192.168.1.1"

    Returns:
        4-byte IP address

    Raises:
        InvalidIPError: If IP address format is invalid
    """
    if not ip_str:
        raise InvalidIPError("IP address cannot be empty")

    try:
        # Use ipaddress module for robust validation
        addr = ipaddress.IPv4Address(ip_str)
        return addr.packed
    except ipaddress.AddressValueError as e:
        raise InvalidIPError(f"Invalid IP address: {ip_str!r}") from e


def decode_bytes(data: bytes) -> str:
    """Decode bytes to string, stripping null terminators."""
    return data.rstrip(b"\x00").decode("utf-8", errors="replace")


# =============================================================================
# Socket Utilities
# =============================================================================


def get_mac(ifname: str) -> bytes:
    """Get MAC address of network interface.

    Args:
        ifname: Network interface name (e.g., "eth0")

    Returns:
        6-byte MAC address

    Raises:
        SocketError: If interface doesn't exist or ioctl fails

    Note:
        This function is Linux-specific (uses ioctl).
    """
    if not ifname:
        raise SocketError("Interface name cannot be empty")

    try:
        with socket(AF_INET, SOCK_DGRAM) as s:
            info = ioctl(
                s.fileno(),
                SIOCGIFHWADDR,
                pack("256s", bytes(ifname[:15], "ascii")),
            )
        return info[18:24]
    except OSError as e:
        raise SocketError(f"Failed to get MAC address for {ifname!r}: {e}") from e


def ethernet_socket(interface: str, ethertype: int = None) -> socket:
    """Create raw Ethernet socket bound to interface.

    Args:
        interface: Network interface name
        ethertype: Ethernet type to filter. If None, receives all packets
                   (needed for VLAN-tagged responses). Default: ETH_P_ALL.

    Returns:
        Bound raw socket

    Raises:
        PermissionDeniedError: If not running as root
        SocketError: If socket creation or binding fails

    Note:
        This function is Linux-specific (uses AF_PACKET).
        Uses ETH_P_ALL by default because some devices (e.g., Siemens S7-1200)
        respond with VLAN-tagged frames (0x8100) even to non-VLAN requests.
    """
    if not interface:
        raise SocketError("Interface name cannot be empty")

    # Default to ETH_P_ALL to capture VLAN-tagged responses
    proto = ethertype if ethertype is not None else ETH_P_ALL

    try:
        s = socket(AF_PACKET, SOCK_RAW, htons(proto))
        s.bind((interface, 0))
        return s
    except PermissionError as e:
        raise PermissionDeniedError(
            f"Root privileges required for raw socket access: {e}"
        ) from e
    except OSError as e:
        raise SocketError(f"Failed to create socket on {interface!r}: {e}") from e


def udp_socket(host: str, port: int, timeout: float = 5.0) -> socket:
    """Create connected UDP socket with timeout.

    Args:
        host: Target hostname or IP
        port: Target port number
        timeout: Socket timeout in seconds (default: 5.0)

    Returns:
        Connected UDP socket with timeout set

    Raises:
        SocketError: If socket creation fails
    """
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except OSError as e:
        raise SocketError(f"Failed to create UDP socket to {host}:{port}: {e}") from e


# =============================================================================
# Timeout Context Manager
# =============================================================================


class MaxTimeout:
    """Context manager for time-limited operations.

    Usage:
        with MaxTimeout(10) as t:
            while not t.timed_out:
                # do work

    Attributes:
        seconds: Timeout duration
        remaining: Seconds remaining until timeout
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._die_after: float = 0

    def __enter__(self) -> "MaxTimeout":
        self._die_after = time.time() + self.seconds
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    @property
    def timed_out(self) -> bool:
        """Check if timeout has elapsed."""
        return time.time() > self._die_after

    @property
    def remaining(self) -> float:
        """Get remaining time in seconds."""
        return max(0, self._die_after - time.time())


# Backwards compatibility alias
max_timeout = MaxTimeout


# =============================================================================
# Packet Factory
# =============================================================================

FieldSpec = Union[str, Tuple[str, Union[str, Callable[[bytes], str]]]]


def make_packet(
    name: str,
    fields: Tuple[Tuple[str, FieldSpec], ...],
    statics: Optional[Dict[str, Any]] = None,
    payload: bool = True,
    payload_size_field: Optional[str] = None,
    payload_offset: int = 0,
    vlf: Optional[str] = None,
    vlf_size_field: Optional[str] = None,
) -> Type:
    """Create a packet class from field definitions.

    This factory creates namedtuple-based packet classes that can both
    parse binary data and serialize to bytes.

    Args:
        name: Class name for the packet type
        fields: Tuple of (field_name, format_spec) pairs where format_spec is
                either a struct format string or (format, display_func) tuple
        statics: Dictionary of class-level constants
        payload: Whether packet has variable payload
        payload_size_field: Field name containing payload size (if size is in header)
        payload_offset: Offset to add to payload size field value
        vlf: Variable length field name
        vlf_size_field: Field name containing VLF size

    Returns:
        Packet class that can parse and create packets

    Example:
        >>> Header = make_packet("Header", (
        ...     ("version", "B"),
        ...     ("length", "H"),
        ... ))
        >>> pkt = Header(data)  # Parse from bytes
        >>> pkt = Header(1, 100, payload=b"data")  # Create new
        >>> bytes(pkt)  # Serialize to bytes
    """
    if statics is None:
        statics = {}

    fields_dict = OrderedDict(fields)
    fmt = ">" + "".join(
        (f[0] if isinstance(f, tuple) else f) for f in fields_dict.values()
    )
    size = calcsize(fmt)

    # Build field list for namedtuple
    field_names = list(fields_dict.keys())
    if vlf is not None:
        field_names.append(vlf)
    if payload:
        field_names.append("payload")

    base_tuple = namedtuple(name, field_names)

    class PacketClass(base_tuple):
        """Packet class created by make_packet factory."""

        def __new__(cls, *args: Any, **kwargs: Any) -> "PacketClass":
            # Parse mode: single bytes argument
            if len(args) == 1 and isinstance(args[0], (bytes, memoryview)):
                data = bytes(args[0])

                if len(data) < size:
                    raise ValueError(
                        f"{name}: insufficient data, need {size} bytes, got {len(data)}"
                    )

                # Unpack fixed-size fields
                unpacked = unpack(fmt, data[:size])

                kw: Dict[str, Any] = {}

                # Handle variable length field
                if vlf is not None:
                    vlf_size = unpacked[list(fields_dict.keys()).index(vlf_size_field)]
                    kw[vlf] = data[size : size + vlf_size]
                    vlf_actual_size = vlf_size
                else:
                    vlf_actual_size = 0

                # Handle payload
                if payload:
                    if payload_size_field is not None:
                        pl_size = (
                            unpacked[list(fields_dict.keys()).index(payload_size_field)]
                            + payload_offset
                        )
                        kw["payload"] = data[
                            size + vlf_actual_size : size + vlf_actual_size + pl_size
                        ]
                    else:
                        kw["payload"] = data[size + vlf_actual_size :]

                return base_tuple.__new__(cls, *unpacked, **kw)

            # Create mode: explicit field values
            return base_tuple.__new__(cls, *args, **kwargs)

        def __repr__(self) -> str:
            """Detailed representation for debugging."""
            field_strs = []
            for k in fields_dict.keys():
                v = getattr(self, k)
                if isinstance(v, bytes) and len(v) <= 6:
                    field_strs.append(f"{k}={v.hex()}")
                elif isinstance(v, bytes):
                    field_strs.append(f"{k}=<{len(v)} bytes>")
                elif isinstance(v, int):
                    field_strs.append(f"{k}=0x{v:x}")
                else:
                    field_strs.append(f"{k}={v!r}")
            return f"{name}({', '.join(field_strs)})"

        def __str__(self) -> str:
            """Format packet as human-readable string."""
            lines = [f"{name} packet ({len(self)} bytes)"]
            for k, v in fields_dict.items():
                value = getattr(self, k)
                if isinstance(v, tuple):
                    if isinstance(v[1], str):
                        formatted = v[1] % value
                    else:
                        formatted = v[1](value)
                else:
                    formatted = str(value)
                lines.append(f"  {k}: {formatted}")
            return "\n".join(lines)

        def __bytes__(self) -> bytes:
            """Serialize packet to bytes."""
            packed = pack(fmt, *(getattr(self, key) for key in fields_dict.keys()))
            if vlf is not None:
                packed += bytes(getattr(self, vlf))
            if payload:
                packed += bytes(self.payload)
            return packed

        def __len__(self) -> int:
            """Get total packet size in bytes."""
            total = size
            if vlf is not None:
                total += len(bytes(getattr(self, vlf)))
            if payload:
                total += len(self.payload)
            return total

    # Set class attributes
    PacketClass.fmt = fmt
    PacketClass.fmt_size = size
    PacketClass.__name__ = name
    PacketClass.__qualname__ = name

    for k, v in statics.items():
        setattr(PacketClass, k, v)

    return PacketClass
