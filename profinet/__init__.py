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
    DCPResponseCode,
    send_discover,
    send_request,
    read_response,
    get_param,
    set_param,
    set_ip,
    signal_device,
    reset_to_factory,
    # Constants
    DCP_MAX_NAME_LENGTH,
    DCP_OPTION_IP,
    DCP_OPTION_DEVICE,
    DCP_OPTION_DHCP,
    DCP_OPTION_LLDP,
    DCP_OPTION_CONTROL,
    DCP_OPTION_DEVICE_INITIATIVE,
    DCP_OPTION_ALL,
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
    epm_lookup,
    # Data classes
    PortStatistics,
    LinkData,
    PortInfo,
    InterfaceInfo,
    DiagnosisEntry,
    ARInfo,
    LogEntry,
    EPMEndpoint,
    MAU_TYPES,
    # RPC Constants
    RPC_PORT,
    RPC_BIND_PORT,
    UUID_NULL,
    UUID_EPM_V4,
    UUID_PNIO_DEVICE,
    UUID_PNIO_CONTROLLER,
    PNIO_DEVICE_INTERFACE_VERSION,
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
from . import blocks

from .blocks import (
    # Data classes for block parsing
    BlockHeader,
    SlotInfo,
    PeerInfo,
    PDRealData,
    RealIdentificationData,
    # Parsing functions
    parse_block_header,
    parse_multiple_block_header,
    parse_pd_interface_data_real,
    parse_pd_port_data_real,
    parse_pd_real_data,
    parse_real_identification_data,
    parse_port_statistics,
)

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

__version__ = "0.3.0"
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
    "DCPResponseCode",
    "send_discover",
    "send_request",
    "read_response",
    "get_param",
    "set_param",
    "set_ip",
    "signal_device",
    "reset_to_factory",
    # DCP constants
    "DCP_MAX_NAME_LENGTH",
    "DCP_OPTION_IP",
    "DCP_OPTION_DEVICE",
    "DCP_OPTION_DHCP",
    "DCP_OPTION_LLDP",
    "DCP_OPTION_CONTROL",
    "DCP_OPTION_DEVICE_INITIATIVE",
    "DCP_OPTION_ALL",
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
    "epm_lookup",
    "EPMEndpoint",
    # RPC constants
    "RPC_PORT",
    "RPC_BIND_PORT",
    "UUID_NULL",
    "UUID_EPM_V4",
    "UUID_PNIO_DEVICE",
    "UUID_PNIO_CONTROLLER",
    "PNIO_DEVICE_INTERFACE_VERSION",
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
    # Blocks module
    "BlockHeader",
    "SlotInfo",
    "PeerInfo",
    "PDRealData",
    "RealIdentificationData",
    "parse_block_header",
    "parse_multiple_block_header",
    "parse_pd_interface_data_real",
    "parse_pd_port_data_real",
    "parse_pd_real_data",
    "parse_real_identification_data",
    "parse_port_statistics",
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
