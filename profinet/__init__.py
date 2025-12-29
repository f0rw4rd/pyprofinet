"""
PROFINET IO-Controller Library

A Python library for PROFINET IO communication, supporting:
- DCP (Discovery and Configuration Protocol) for device discovery
- DCE/RPC for acyclic parameter read/write operations
- IM0/IM1 device identification data access

This library acts as an IO-Controller, allowing connection to and
communication with PROFINET IO-Devices.

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet

    Modernized for Python 3.8+ by f0rw4rd (2024)
    https://github.com/f0rw4rd/profinet-py
"""

from .protocol import (
    EthernetHeader,
    EthernetVLANHeader,
    PNDCPHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    IPConfiguration,
    PNRPCHeader,
    PNNRDData,
    PNIODHeader,
    PNBlockHeader,
    PNARBlockRequest,
    PNIODReleaseBlock,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNInM4,
    PNInM5,
)

from .dcp import (
    DCPDeviceDescription,
    send_discover,
    send_request,
    read_response,
    get_param,
    set_param,
    set_ip,
    signal_device,
    reset_to_factory,
    # Constants
    RESET_MODE_COMMUNICATION,
    RESET_MODE_APPLICATION,
    RESET_MODE_ENGINEERING,
    RESET_MODE_ALL_DATA,
    RESET_MODE_DEVICE,
    RESET_MODE_FACTORY,
)

from .rpc import (
    RPCCon,
    get_station_info,
    # Data classes
    PortStatistics,
    LinkData,
    PortInfo,
    InterfaceInfo,
    DiagnosisEntry,
    ARInfo,
    LogEntry,
    MAU_TYPES,
)

from .diagnosis import (
    # Diagnosis data classes
    DiagnosisData,
    ChannelDiagnosis,
    ExtChannelDiagnosis,
    QualifiedChannelDiagnosis,
    ChannelProperties,
    # Enums
    UserStructureIdentifier,
    ChannelType,
    ChannelDirection,
    ChannelAccumulative,
    ChannelSpecifier,
    # Parsing functions
    parse_diagnosis_block,
    parse_diagnosis_simple,
    decode_channel_error_type,
    decode_ext_channel_error_type,
    # Constants
    CHANNEL_ERROR_TYPES,
    EXT_CHANNEL_ERROR_TYPES_MAP,
)

from .util import (
    ethernet_socket,
    udp_socket,
    get_mac,
    s2mac,
    mac2s,
    s2ip,
    ip2s,
    to_hex,
)

from .vendors import (
    profinet_vendor_map,
    get_vendor_name,
    lookup_vendor,
)

from . import indices

from .exceptions import (
    ProfinetError,
    DCPError,
    DCPTimeoutError,
    DCPDeviceNotFoundError,
    RPCError,
    RPCTimeoutError,
    RPCFaultError,
    RPCConnectionError,
    PNIOError,
    ValidationError,
    InvalidMACError,
    InvalidIPError,
    SocketError,
    PermissionDeniedError,
)

__version__ = "0.2.0"
__all__ = [
    # Protocol structures
    "EthernetHeader",
    "EthernetVLANHeader",
    "PNDCPHeader",
    "PNDCPBlock",
    "PNDCPBlockRequest",
    "IPConfiguration",
    "PNRPCHeader",
    "PNNRDData",
    "PNIODHeader",
    "PNBlockHeader",
    "PNARBlockRequest",
    "PNIODReleaseBlock",
    "PNInM0",
    "PNInM1",
    "PNInM2",
    "PNInM3",
    "PNInM4",
    "PNInM5",
    # DCP functions
    "DCPDeviceDescription",
    "send_discover",
    "send_request",
    "read_response",
    "get_param",
    "set_param",
    "set_ip",
    "signal_device",
    "reset_to_factory",
    # Reset modes
    "RESET_MODE_COMMUNICATION",
    "RESET_MODE_APPLICATION",
    "RESET_MODE_ENGINEERING",
    "RESET_MODE_ALL_DATA",
    "RESET_MODE_DEVICE",
    "RESET_MODE_FACTORY",
    # RPC
    "RPCCon",
    "get_station_info",
    # Utilities
    "ethernet_socket",
    "udp_socket",
    "get_mac",
    "s2mac",
    "mac2s",
    "s2ip",
    "ip2s",
    "to_hex",
    # Vendor lookup
    "profinet_vendor_map",
    "get_vendor_name",
    "lookup_vendor",
    # Diagnosis
    "DiagnosisData",
    "ChannelDiagnosis",
    "ExtChannelDiagnosis",
    "QualifiedChannelDiagnosis",
    "ChannelProperties",
    "UserStructureIdentifier",
    "ChannelType",
    "ChannelDirection",
    "ChannelAccumulative",
    "ChannelSpecifier",
    "parse_diagnosis_block",
    "parse_diagnosis_simple",
    "decode_channel_error_type",
    "decode_ext_channel_error_type",
    "CHANNEL_ERROR_TYPES",
    "EXT_CHANNEL_ERROR_TYPES_MAP",
    # Exceptions
    "ProfinetError",
    "DCPError",
    "DCPTimeoutError",
    "DCPDeviceNotFoundError",
    "RPCError",
    "RPCTimeoutError",
    "RPCFaultError",
    "RPCConnectionError",
    "PNIOError",
    "ValidationError",
    "InvalidMACError",
    "InvalidIPError",
    "SocketError",
    "PermissionDeniedError",
]
