"""
PROFINET protocol packet definitions.

Defines packet structures for:
- DCP (Discovery and Configuration Protocol)
- DCE/RPC (Remote Procedure Call)
- PNIO (PROFINET IO) data blocks

Credits:
    Original implementation by Alfred Krohmer (2015)
    https://github.com/alfredkrohmer/profinet
"""

from __future__ import annotations

from collections import namedtuple
from typing import Tuple

from .util import decode_bytes, mac2s, make_packet, s2ip


# =============================================================================
# DCP - Discovery and Configuration Protocol
# =============================================================================

EthernetHeader = make_packet(
    "EthernetHeader",
    (
        ("dst", ("6s", mac2s)),
        ("src", ("6s", mac2s)),
        ("type", ("H", "0x%04X")),
    ),
)

EthernetVLANHeader = make_packet(
    "EthernetVLANHeader",
    (
        ("dst", ("6s", mac2s)),
        ("src", ("6s", mac2s)),
        ("tpid", ("H", "0x%04X")),
        ("tci", ("H", "0x%04X")),
        ("type", ("H", "0x%04X")),
    ),
)

PNDCPHeader = make_packet(
    "PNDCPHeader",
    (
        ("frame_id", ("H", "0x%04X")),
        ("service_id", "B"),
        ("service_type", "B"),
        ("xid", ("I", "0x%08X")),
        ("resp", "H"),
        ("length", "H"),
    ),
    statics={
        "ETHER_TYPE": 0x8892,
        # Service IDs
        "GET": 3,
        "SET": 4,
        "IDENTIFY": 5,
        # Service Types
        "REQUEST": 0,
        "RESPONSE": 1,
    },
)


class IPConfiguration(namedtuple("IPConfiguration", ["address", "netmask", "gateway"])):
    """IP configuration data from DCP response."""

    def __str__(self) -> str:
        return (
            f"IP Configuration\n"
            f"  Address: {self.address}\n"
            f"  Netmask: {self.netmask}\n"
            f"  Gateway: {self.gateway}"
        )


class PNDCPBlockRequest(
    make_packet(
        "PNDCPBlockRequest",
        (
            ("option", "B"),
            ("suboption", "B"),
            ("length", "H"),
        ),
        payload_size_field="length",
    )
):
    """DCP request block."""

    def parse_ip(self) -> IPConfiguration:
        """Parse IP configuration from payload."""
        return IPConfiguration(
            s2ip(self.payload[0:4]),
            s2ip(self.payload[4:8]),
            s2ip(self.payload[8:12]),
        )


class PNDCPBlock(
    make_packet(
        "PNDCPBlock",
        (
            ("option", "B"),
            ("suboption", "B"),
            ("length", "H"),
            ("status", "H"),
        ),
        payload_size_field="length",
        payload_offset=-2,
    )
):
    """DCP response block."""

    # Block option/suboption constants
    IP_ADDRESS: Tuple[int, int] = (1, 2)
    NAME_OF_STATION: Tuple[int, int] = (2, 2)
    DEVICE_ID: Tuple[int, int] = (2, 3)
    ALL: Tuple[int, int] = (0xFF, 0xFF)

    def parse_ip(self) -> IPConfiguration:
        """Parse IP configuration from payload."""
        return IPConfiguration(
            s2ip(self.payload[0:4]),
            s2ip(self.payload[4:8]),
            s2ip(self.payload[8:12]),
        )


# =============================================================================
# DCE/RPC - Remote Procedure Call
# =============================================================================

# PROFINET UUID suffix
_UUID = [0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D]

PNRPCHeader = make_packet(
    "PNRPCHeader",
    (
        ("version", "B"),
        ("packet_type", "B"),
        ("flags1", "B"),
        ("flags2", "B"),
        ("drep", "3s"),  # Data representation
        ("serial_high", "B"),
        ("object_uuid", "16s"),
        ("interface_uuid", "16s"),
        ("activity_uuid", "16s"),
        ("server_boot_time", "I"),
        ("interface_version", "I"),
        ("sequence_number", "I"),
        ("operation_number", "H"),
        ("interface_hint", "H"),
        ("activity_hint", "H"),
        ("length_of_body", "H"),
        ("fragment_number", "H"),
        ("authentication_protocol", "B"),
        ("serial_low", "B"),
    ),
    statics={
        # Packet types
        "REQUEST": 0x00,
        "PING": 0x01,
        "RESPONSE": 0x02,
        "FAULT": 0x03,
        "WORKING": 0x04,
        "PONG": 0x05,
        "REJECT": 0x06,
        "ACK": 0x07,
        "CANCEL": 0x08,
        "FRAG_ACK": 0x09,
        "CANCEL_ACK": 0x0A,
        # Operation numbers
        "CONNECT": 0x00,
        "RELEASE": 0x01,
        "READ": 0x02,
        "WRITE": 0x03,
        "CONTROL": 0x04,
        "IMPLICIT_READ": 0x05,
        # Interface UUIDs
        "IFACE_UUID_DEVICE": bytes([0xDE, 0xA0, 0x00, 0x01] + _UUID),
        "IFACE_UUID_CONTROLLER": bytes([0xDE, 0xA0, 0x00, 0x02] + _UUID),
        "IFACE_UUID_SUPERVISOR": bytes([0xDE, 0xA0, 0x00, 0x03] + _UUID),
        "IFACE_UUID_PARAMSERVER": bytes([0xDE, 0xA0, 0x00, 0x04] + _UUID),
        # Object UUID prefix
        "OBJECT_UUID_PREFIX": bytes(
            [0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71]
        ),
    },
)


PNNRDData = make_packet(
    "PNNRDData",
    (
        ("args_maximum_status", "I"),
        ("args_length", "I"),
        ("maximum_count", "I"),
        ("offset", "I"),
        ("actual_count", "I"),
    ),
)


PNIODHeader = make_packet(
    "PNIODHeader",
    (
        ("block_header", "6s"),
        ("sequence_number", "H"),
        ("ar_uuid", "16s"),
        ("api", "I"),
        ("slot", "H"),
        ("subslot", "H"),
        ("padding1", "H"),
        ("index", "H"),
        ("length", "I"),
        ("target_ar_uuid", "16s"),
        ("padding2", "8s"),
    ),
)


PNBlockHeader = make_packet(
    "PNBlockHeader",
    (
        ("block_type", "H"),
        ("block_length", "H"),
        ("block_version_high", "B"),
        ("block_version_low", "B"),
    ),
    payload=False,
    statics={
        "IDOReadRequestHeader": 0x0009,
        "IODReadResponseHeader": 0x8009,
        "InM0": 0x0020,
        "InM0FilterDataSubModul": 0x0030,
        "InM0FilterDataModul": 0x0031,
        "InM0FilterDataDevice": 0x0032,
    },
)


PNARBlockRequest = make_packet(
    "PNARBlockRequest",
    (
        ("block_header", "6s"),
        ("ar_type", "H"),
        ("ar_uuid", "16s"),
        ("session_key", "H"),
        ("cm_initiator_mac_address", "6s"),
        ("cm_initiator_object_uuid", "16s"),
        ("ar_properties", "I"),
        ("cm_initiator_activity_timeout_factor", "H"),
        ("initiator_udp_rtport", "H"),
        ("station_name_length", "H"),
    ),
    vlf="cm_initiator_station_name",
    vlf_size_field="station_name_length",
)


PNIODReleaseBlock = make_packet(
    "PNIODReleaseBlock",
    (
        ("block_header", "6s"),
        ("padding1", "H"),
        ("ar_uuid", "16s"),
        ("session_key", "H"),
        ("padding2", "H"),
        ("control_command", "H"),
        ("control_block_properties", "H"),
    ),
)


# =============================================================================
# I&M (Identification & Maintenance) Data
# =============================================================================

PNInM0 = make_packet(
    "PNInM0",
    (
        ("block_header", "6s"),
        ("vendor_id_high", "B"),
        ("vendor_id_low", "B"),
        ("order_id", ("20s", decode_bytes)),
        ("im_serial_number", ("16s", decode_bytes)),
        ("im_hardware_revision", "H"),
        ("sw_revision_prefix", "B"),
        ("im_sw_revision_functional_enhancement", "B"),
        ("im_sw_revision_bug_fix", "B"),
        ("im_sw_revision_internal_change", "B"),
        ("im_revision_counter", "H"),
        ("im_profile_id", "H"),
        ("im_profile_specific_type", "H"),
        ("im_version", "H"),
        ("im_supported", "H"),
    ),
    payload=False,
    statics={"IDX": 0xAFF0},
)


PNInM1 = make_packet(
    "PNInM1",
    (
        ("block_header", "6s"),
        ("im_tag_function", ("32s", decode_bytes)),
        ("im_tag_location", ("22s", decode_bytes)),
    ),
    payload=False,
    statics={"IDX": 0xAFF1},
)


PNInM2 = make_packet(
    "PNInM2",
    (
        ("block_header", "6s"),
        ("im_date", ("16s", decode_bytes)),  # YYYY-MM-DD HH:MM format
    ),
    payload=False,
    statics={"IDX": 0xAFF2},
)


PNInM3 = make_packet(
    "PNInM3",
    (
        ("block_header", "6s"),
        ("im_descriptor", ("54s", decode_bytes)),  # General descriptor
    ),
    payload=False,
    statics={"IDX": 0xAFF3},
)


PNInM4 = make_packet(
    "PNInM4",
    (
        ("block_header", "6s"),
        ("im_signature", "54s"),  # PROFIsafe signature (binary)
    ),
    payload=False,
    statics={"IDX": 0xAFF4},
)


PNInM5 = make_packet(
    "PNInM5",
    (
        ("block_header", "6s"),
        ("im_annotation", ("64s", decode_bytes)),  # Annotation string
    ),
    payload=False,
    statics={"IDX": 0xAFF5},
)
