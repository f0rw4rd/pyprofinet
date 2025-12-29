"""
PROFINET DCP (Discovery and Configuration Protocol) implementation.

Provides device discovery and basic configuration operations:
- send_discover(): Multicast discovery request
- read_response(): Collect and parse discovery responses
- get_param(): Read device parameter (name, IP)
- set_param(): Write device parameter

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet
"""

from __future__ import annotations

import logging
import random
import time
from socket import socket, timeout as SocketTimeout
from struct import unpack
from typing import Any, Dict, Optional, Tuple

from .exceptions import DCPError, DCPDeviceNotFoundError, DCPTimeoutError
from .protocol import (
    EthernetHeader,
    EthernetVLANHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    PNDCPHeader,
)
from .util import (
    MAX_ETHERNET_FRAME,
    PROFINET_ETHERTYPE,
    VLAN_ETHERTYPE,
    mac2s,
    max_timeout,
    s2ip,
    s2mac,
)
from .vendors import get_vendor_name

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# DCP multicast address
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"

# DCP Frame IDs
DCP_IDENTIFY_FRAME_ID = 0xFEFE
DCP_GET_SET_FRAME_ID = 0xFEFD

# DCP Options
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE = 0x02
DCP_OPTION_DHCP = 0x03
DCP_OPTION_CONTROL = 0x05
DCP_OPTION_DEVICE_INITIATIVE = 0x06
DCP_OPTION_ALL = 0xFF

# DCP SubOptions for Control (Option 5)
DCP_SUBOPTION_CONTROL_START = 0x01
DCP_SUBOPTION_CONTROL_STOP = 0x02
DCP_SUBOPTION_CONTROL_SIGNAL = 0x03
DCP_SUBOPTION_CONTROL_RESPONSE = 0x04
DCP_SUBOPTION_CONTROL_RESET_FACTORY = 0x05
DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY = 0x06

# Reset modes for Reset to Factory
RESET_MODE_COMMUNICATION = 0x0002  # Mode 2: Reset communication params (mandatory)
RESET_MODE_APPLICATION = 0x0004   # Mode 1: Reset application data
RESET_MODE_ENGINEERING = 0x0008   # Mode 3: Reset engineering data
RESET_MODE_ALL_DATA = 0x0010      # Mode 4: Reset all data
RESET_MODE_DEVICE = 0x0020        # Mode 8: Reset device
RESET_MODE_FACTORY = 0x0040       # Mode 9: Reset to factory image

# Parameter name mappings
PARAMS: Dict[str, Tuple[int, int]] = {
    "name": PNDCPBlock.NAME_OF_STATION,
    "ip": PNDCPBlock.IP_ADDRESS,
}


def _generate_xid() -> int:
    """Generate random transaction ID for DCP requests."""
    return random.randint(0, 0xFFFFFFFF)


# =============================================================================
# Device Description
# =============================================================================


class DCPDeviceDescription:
    """Parsed PROFINET device information from DCP response.

    Attributes:
        mac: MAC address string
        name: Station name
        ip: IP address string
        netmask: Network mask string
        gateway: Gateway address string
        vendor_high: High byte of vendor ID
        vendor_low: Low byte of vendor ID
        device_high: High byte of device ID
        device_low: Low byte of device ID
    """

    def __init__(self, mac: bytes, blocks: Dict[Tuple[int, int], bytes]) -> None:
        """Initialize device description from DCP blocks.

        Args:
            mac: Device MAC address (6 bytes)
            blocks: Dictionary of (option, suboption) -> payload mappings

        Raises:
            DCPError: If required blocks are missing
        """
        self.mac = mac2s(mac)

        # Handle station name (required)
        name_block = blocks.get(PNDCPBlock.NAME_OF_STATION)
        if name_block is not None:
            self.name = name_block.decode("utf-8", errors="replace")
        else:
            self.name = ""
            logger.warning(f"Device {self.mac} has no station name")

        # Handle IP configuration (required)
        ip_block = blocks.get(PNDCPBlock.IP_ADDRESS)
        if ip_block is not None and len(ip_block) >= 12:
            self.ip = s2ip(ip_block[0:4])
            self.netmask = s2ip(ip_block[4:8])
            self.gateway = s2ip(ip_block[8:12])
        else:
            self.ip = "0.0.0.0"
            self.netmask = "0.0.0.0"
            self.gateway = "0.0.0.0"
            logger.warning(f"Device {self.mac} has no IP configuration")

        # Handle device ID (optional)
        device_id = blocks.get(PNDCPBlock.DEVICE_ID, b"\x00\x00\x00\x00")
        if len(device_id) >= 4:
            self.vendor_high, self.vendor_low, self.device_high, self.device_low = unpack(
                ">BBBB", device_id[0:4]
            )
        else:
            self.vendor_high = 0
            self.vendor_low = 0
            self.device_high = 0
            self.device_low = 0

    @property
    def vendor_id(self) -> int:
        """Get 16-bit vendor ID."""
        return (self.vendor_high << 8) | self.vendor_low

    @property
    def device_id(self) -> int:
        """Get 16-bit device ID."""
        return (self.device_high << 8) | self.device_low

    @property
    def vendor_name(self) -> str:
        """Get vendor name from ID lookup."""
        return get_vendor_name(self.vendor_id)

    def __repr__(self) -> str:
        return (
            f"DCPDeviceDescription(name={self.name!r}, ip={self.ip}, "
            f"mac={self.mac}, vendor={self.vendor_name!r})"
        )

    def __str__(self) -> str:
        return (
            f"PROFINET Device: {self.name}\n"
            f"  MAC:     {self.mac}\n"
            f"  IP:      {self.ip}\n"
            f"  Netmask: {self.netmask}\n"
            f"  Gateway: {self.gateway}\n"
            f"  Vendor:  {self.vendor_name} (0x{self.vendor_id:04X})\n"
            f"  Device:  0x{self.device_id:04X}"
        )


# =============================================================================
# DCP Operations
# =============================================================================


def get_param(
    sock: socket,
    src: bytes,
    target: str,
    param: str,
    timeout_sec: int = 5,
) -> Optional[bytes]:
    """Read a parameter from a PROFINET device.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        param: Parameter name ("name" or "ip")
        timeout_sec: Timeout in seconds

    Returns:
        Parameter value as bytes, or None if not found

    Raises:
        DCPError: If parameter name is unknown
    """
    if param not in PARAMS:
        raise DCPError(f"Unknown parameter: {param!r}. Valid: {list(PARAMS.keys())}")

    dst = s2mac(target)
    param_tuple = PARAMS[param]
    xid = _generate_xid()

    block = PNDCPBlockRequest(param_tuple[0], param_tuple[1], 0, payload=bytes())
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.GET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        2,
        payload=block,
    )
    eth = EthernetVLANHeader(
        dst, src, VLAN_ETHERTYPE, 0, PROFINET_ETHERTYPE, payload=dcp
    )

    sock.send(bytes(eth))

    responses = read_response(sock, src, timeout_sec=timeout_sec, once=True)
    if responses:
        first_response = list(responses.values())[0]
        return first_response.get(param_tuple)
    return None


def set_param(
    sock: socket,
    src: bytes,
    target: str,
    param: str,
    value: str,
    timeout_sec: int = 5,
) -> bool:
    """Write a parameter to a PROFINET device.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        param: Parameter name ("name" or "ip")
        value: New parameter value
        timeout_sec: Timeout in seconds

    Returns:
        True if response received, False if timeout

    Raises:
        DCPError: If parameter name is unknown
    """
    if param not in PARAMS:
        raise DCPError(f"Unknown parameter: {param!r}. Valid: {list(PARAMS.keys())}")

    dst = s2mac(target)
    param_tuple = PARAMS[param]
    value_bytes = bytes(value, encoding="ascii")
    xid = _generate_xid()

    # Add padding for block qualifier (2 bytes)
    block = PNDCPBlockRequest(
        param_tuple[0],
        param_tuple[1],
        len(value_bytes) + 2,
        payload=bytes([0x00, 0x00]) + value_bytes,
    )

    # Calculate length with padding
    padding = 1 if len(value_bytes) % 2 == 1 else 0
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(value_bytes) + 6 + padding,
        payload=block,
    )
    eth = EthernetVLANHeader(
        dst, src, VLAN_ETHERTYPE, 0, PROFINET_ETHERTYPE, payload=dcp
    )

    sock.send(bytes(eth))

    # Wait for response
    sock.settimeout(float(timeout_sec))
    try:
        sock.recv(MAX_ETHERNET_FRAME)
        # Wait for device to process
        time.sleep(2)
        return True
    except SocketTimeout:
        logger.warning(f"No response from {target} for set_param")
        return False


def set_ip(
    sock: socket,
    src: bytes,
    target: str,
    ip: str,
    netmask: str,
    gateway: str,
    timeout_sec: int = 5,
) -> bool:
    """Set IP configuration on a PROFINET device via DCP.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        ip: New IP address (e.g., "192.168.10.3")
        netmask: Subnet mask (e.g., "255.255.255.0")
        gateway: Gateway address (e.g., "192.168.10.1")
        timeout_sec: Timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Convert IP strings to bytes (4 bytes each)
    def ip_to_bytes(ip_str: str) -> bytes:
        parts = ip_str.split(".")
        return bytes([int(p) for p in parts])

    ip_bytes = ip_to_bytes(ip)
    netmask_bytes = ip_to_bytes(netmask)
    gateway_bytes = ip_to_bytes(gateway)

    # IP block payload: 2 bytes qualifier + 4 IP + 4 netmask + 4 gateway = 14 bytes
    value_bytes = ip_bytes + netmask_bytes + gateway_bytes

    block = PNDCPBlockRequest(
        PNDCPBlock.IP_ADDRESS[0],  # Option (0x01 = IP)
        PNDCPBlock.IP_ADDRESS[1],  # Suboption (0x02 = IP Suite)
        len(value_bytes) + 2,  # Length includes 2-byte qualifier
        payload=bytes([0x00, 0x01]) + value_bytes,  # 0x0001 = set temporary
    )

    # Calculate length with padding (blocks are 2-byte aligned)
    padding = 0 if len(value_bytes) % 2 == 0 else 1
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(value_bytes) + 6 + padding,
        payload=block,
    )
    eth = EthernetVLANHeader(
        dst, src, VLAN_ETHERTYPE, 0, PROFINET_ETHERTYPE, payload=dcp
    )

    sock.send(bytes(eth))

    # Wait for response
    sock.settimeout(float(timeout_sec))
    try:
        sock.recv(MAX_ETHERNET_FRAME)
        # Wait for device to process
        time.sleep(2)
        return True
    except SocketTimeout:
        logger.warning(f"No response from {target} for set_ip")
        return False


def send_discover(sock: socket, src: bytes) -> None:
    """Send DCP Identify multicast request.

    Sends an Identify request to the PROFINET multicast address
    to discover all devices on the network.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
    """
    xid = _generate_xid()

    block = PNDCPBlockRequest(0xFF, 0xFF, 0, payload=bytes())
    dcp = PNDCPHeader(
        DCP_IDENTIFY_FRAME_ID,
        PNDCPHeader.IDENTIFY,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block),
        payload=block,
    )
    eth = EthernetVLANHeader(
        s2mac(DCP_MULTICAST_MAC),
        src,
        VLAN_ETHERTYPE,
        0,
        PROFINET_ETHERTYPE,
        payload=dcp,
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Identify request (xid=0x{xid:08X})")


def send_request(
    sock: socket,
    src: bytes,
    block_type: Tuple[int, int],
    value: bytes,
) -> None:
    """Send DCP Identify request with specific filter.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        block_type: (option, suboption) tuple to filter
        value: Filter value bytes
    """
    xid = _generate_xid()

    block = PNDCPBlockRequest(block_type[0], block_type[1], len(value), payload=value)
    dcp = PNDCPHeader(
        DCP_IDENTIFY_FRAME_ID,
        PNDCPHeader.IDENTIFY,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block),
        payload=block,
    )
    eth = EthernetVLANHeader(
        s2mac(DCP_MULTICAST_MAC),
        src,
        VLAN_ETHERTYPE,
        0,
        PROFINET_ETHERTYPE,
        payload=dcp,
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP request for {block_type} (xid=0x{xid:08X})")


def read_response(
    sock: socket,
    my_mac: bytes,
    timeout_sec: int = 20,
    once: bool = False,
    debug: bool = False,
) -> Dict[bytes, Dict[Any, Any]]:
    """Read and parse DCP responses.

    Args:
        sock: Raw Ethernet socket
        my_mac: Our MAC address (6 bytes) for filtering
        timeout_sec: Maximum time to wait for responses
        once: If True, return after first response
        debug: If True, log debug information

    Returns:
        Dictionary mapping MAC addresses to parsed block data
    """
    result: Dict[bytes, Dict[Any, Any]] = {}
    sock.settimeout(2.0)

    try:
        with max_timeout(timeout_sec) as timer:
            while not timer.timed_out:
                try:
                    data = sock.recv(MAX_ETHERNET_FRAME)
                except SocketTimeout:
                    continue
                except OSError as e:
                    logger.debug(f"Socket error during receive: {e}")
                    continue

                if len(data) < 14:  # Minimum Ethernet header
                    continue

                # Parse Ethernet header
                try:
                    eth = EthernetHeader(data)
                except ValueError as e:
                    logger.debug(f"Failed to parse Ethernet header: {e}")
                    continue

                # Filter: only packets to us with PROFINET type
                if eth.dst != my_mac or eth.type != PROFINET_ETHERTYPE:
                    continue

                if debug:
                    logger.info(f"DCP response from {mac2s(eth.src)}")

                # Parse DCP header
                try:
                    dcp = PNDCPHeader(eth.payload)
                except ValueError as e:
                    logger.debug(f"Failed to parse DCP header: {e}")
                    continue

                # Filter: only DCP responses
                if dcp.service_type != PNDCPHeader.RESPONSE:
                    continue

                # Parse DCP blocks
                blocks = dcp.payload
                length = dcp.length
                parsed: Dict[Any, Any] = {}

                while length > 6:
                    try:
                        block = PNDCPBlock(blocks)
                    except ValueError as e:
                        logger.debug(f"Failed to parse DCP block: {e}")
                        break

                    block_option = (block.option, block.suboption)
                    parsed[block_option] = block.payload

                    if block_option == PNDCPBlock.NAME_OF_STATION:
                        if debug:
                            logger.info(f"  Name: {block.payload.decode('utf-8', errors='replace')}")
                        parsed["name"] = block.payload

                    elif block_option == PNDCPBlock.IP_ADDRESS:
                        if debug:
                            logger.info(f"  IP: {s2ip(block.payload[0:4])}")
                        parsed["ip"] = s2ip(block.payload[0:4])

                    elif block_option == PNDCPBlock.DEVICE_ID:
                        parsed["devId"] = block.payload

                    # Handle padding (blocks are 2-byte aligned)
                    block_len = block.length
                    if block_len % 2 == 1:
                        block_len += 1

                    # Move to next block (4 bytes header + payload + padding)
                    blocks = blocks[block_len + 4:]
                    length -= 4 + block_len

                result[eth.src] = parsed

                if once:
                    break

    except TimeoutError:
        pass

    logger.debug(f"DCP discovery found {len(result)} devices")
    return result


def signal_device(
    sock: socket,
    src: bytes,
    target: str,
    duration_ms: int = 3000,
    timeout_sec: int = 5,
) -> bool:
    """Send DCP Signal command to flash device LEDs.

    This sends a Control/Signal request that causes the device to
    flash its identification LEDs for the specified duration.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        duration_ms: Flash duration in milliseconds (default: 3000)
        timeout_sec: Response timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Signal block data: BlockInfo (2 bytes) + SignalValue (2 bytes)
    # BlockInfo: 0x0001 = temporary signal
    # SignalValue: duration in 100ms units
    duration_units = max(1, duration_ms // 100)  # Convert to 100ms units
    block_info = bytes([0x00, 0x01])  # Temporary signal
    signal_value = duration_units.to_bytes(2, 'big')
    block_data = block_info + signal_value

    block = PNDCPBlockRequest(
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_SIGNAL,
        len(block_data),
        payload=block_data,
    )

    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block_data) + 4,  # block header (4) + data
        payload=block,
    )
    eth = EthernetVLANHeader(
        dst, src, VLAN_ETHERTYPE, 0, PROFINET_ETHERTYPE, payload=dcp
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Signal request to {target} (duration={duration_ms}ms)")

    # Wait for response
    sock.settimeout(float(timeout_sec))
    try:
        sock.recv(MAX_ETHERNET_FRAME)
        return True
    except SocketTimeout:
        logger.warning(f"No response from {target} for signal command")
        return False


def reset_to_factory(
    sock: socket,
    src: bytes,
    target: str,
    mode: int = RESET_MODE_COMMUNICATION,
    timeout_sec: int = 5,
) -> bool:
    """Send DCP Reset to Factory command.

    WARNING: This will reset device configuration! Use with caution.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        mode: Reset mode bitmask (default: RESET_MODE_COMMUNICATION)
            - RESET_MODE_COMMUNICATION (0x0002): Reset comm params (mandatory)
            - RESET_MODE_APPLICATION (0x0004): Reset application data
            - RESET_MODE_ENGINEERING (0x0008): Reset engineering data
            - RESET_MODE_ALL_DATA (0x0010): Reset all data
            - RESET_MODE_DEVICE (0x0020): Reset device
            - RESET_MODE_FACTORY (0x0040): Reset to factory image
        timeout_sec: Response timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Reset block data: BlockQualifier (2 bytes) with reset mode
    block_qualifier = mode.to_bytes(2, 'big')

    block = PNDCPBlockRequest(
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY,
        len(block_qualifier),
        payload=block_qualifier,
    )

    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block_qualifier) + 4,  # block header (4) + data
        payload=block,
    )
    eth = EthernetVLANHeader(
        dst, src, VLAN_ETHERTYPE, 0, PROFINET_ETHERTYPE, payload=dcp
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Reset to Factory request to {target} (mode=0x{mode:04X})")

    # Wait for response
    sock.settimeout(float(timeout_sec))
    try:
        sock.recv(MAX_ETHERNET_FRAME)
        # Device needs time to reset
        time.sleep(2)
        return True
    except SocketTimeout:
        logger.warning(f"No response from {target} for reset command")
        return False
