"""Tests for profinet.protocol module."""

import pytest
from profinet.protocol import (
    EthernetHeader,
    EthernetVLANHeader,
    PNDCPHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    PNBlockHeader,
)


class TestEthernetHeader:
    """Test EthernetHeader packet structure."""

    def test_parse_ethernet_header(self):
        """Test parsing Ethernet header from bytes."""
        # dst(6) + src(6) + type(2) + payload
        data = (
            b"\x01\x02\x03\x04\x05\x06"  # dst
            + b"\x0a\x0b\x0c\x0d\x0e\x0f"  # src
            + b"\x88\x92"  # type (PROFINET)
            + b"\x00\x00"  # payload
        )

        pkt = EthernetHeader(data)

        assert pkt.dst == b"\x01\x02\x03\x04\x05\x06"
        assert pkt.src == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert pkt.type == 0x8892

    def test_create_ethernet_header(self):
        """Test creating Ethernet header."""
        pkt = EthernetHeader(
            b"\x01\x02\x03\x04\x05\x06",
            b"\x0a\x0b\x0c\x0d\x0e\x0f",
            0x8892,
            payload=b"\x00\x00",
        )

        data = bytes(pkt)
        assert data[:6] == b"\x01\x02\x03\x04\x05\x06"
        assert data[6:12] == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert data[12:14] == b"\x88\x92"


class TestEthernetVLANHeader:
    """Test EthernetVLANHeader packet structure."""

    def test_parse_vlan_header(self):
        """Test parsing VLAN tagged Ethernet header."""
        data = (
            b"\x01\x02\x03\x04\x05\x06"  # dst
            + b"\x0a\x0b\x0c\x0d\x0e\x0f"  # src
            + b"\x81\x00"  # tpid (VLAN ethertype)
            + b"\x00\x00"  # tci (VLAN ID/priority)
            + b"\x88\x92"  # type (inner type - PROFINET)
            + b"\x00"  # payload
        )

        pkt = EthernetVLANHeader(data)

        assert pkt.dst == b"\x01\x02\x03\x04\x05\x06"
        assert pkt.src == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert pkt.tpid == 0x8100
        assert pkt.tci == 0x0000
        assert pkt.type == 0x8892


class TestPNDCPHeader:
    """Test PNDCPHeader packet structure."""

    def test_parse_dcp_header(self):
        """Test parsing DCP header."""
        data = (
            b"\xfe\xfe"  # frame_id (Identify)
            + b"\x05"  # service_id (Identify)
            + b"\x00"  # service_type (Request)
            + b"\x12\x34\x56\x78"  # xid
            + b"\x00\xc0"  # delay
            + b"\x00\x04"  # length
            + b"\xff\xff\x00\x00"  # payload
        )

        pkt = PNDCPHeader(data)

        assert pkt.frame_id == 0xfefe
        assert pkt.service_id == 0x05
        assert pkt.service_type == 0x00
        assert pkt.xid == 0x12345678
        assert pkt.length == 4

    def test_dcp_header_constants(self):
        """Test DCP header constants."""
        assert PNDCPHeader.IDENTIFY == 0x05
        assert PNDCPHeader.GET == 0x03
        assert PNDCPHeader.SET == 0x04
        assert PNDCPHeader.REQUEST == 0x00
        assert PNDCPHeader.RESPONSE == 0x01


class TestPNDCPBlock:
    """Test PNDCPBlock packet structure."""

    def test_parse_dcp_block(self):
        """Test parsing DCP response block."""
        # DCP response block includes status field (2 bytes)
        # Structure: option(1) + suboption(1) + length(2) + status(2) + payload
        # Length includes status, so payload = length - 2 bytes
        data = (
            b"\x02"  # option (Device properties)
            + b"\x02"  # suboption (Name of station)
            + b"\x00\x0d"  # length (13 = 2 bytes status + 11 bytes name)
            + b"\x00\x00"  # status
            + b"test-device"  # payload (11 bytes)
        )

        pkt = PNDCPBlock(data)

        assert pkt.option == 0x02
        assert pkt.suboption == 0x02
        assert pkt.length == 13
        assert pkt.status == 0x0000
        assert pkt.payload == b"test-device"

    def test_dcp_block_constants(self):
        """Test DCP block type constants."""
        assert PNDCPBlock.NAME_OF_STATION == (0x02, 0x02)
        assert PNDCPBlock.IP_ADDRESS == (0x01, 0x02)
        assert PNDCPBlock.DEVICE_ID == (0x02, 0x03)


class TestPNBlockHeader:
    """Test PNBlockHeader packet structure."""

    def test_parse_block_header(self):
        """Test parsing block header."""
        data = (
            b"\x00\x08"  # block_type
            + b"\x00\x3c"  # block_length
            + b"\x01"  # block_version_high
            + b"\x00"  # block_version_low
        )

        pkt = PNBlockHeader(data)

        assert pkt.block_type == 0x0008
        assert pkt.block_length == 60
        assert pkt.block_version_high == 1
        assert pkt.block_version_low == 0

    def test_block_header_constants(self):
        """Test block header constants."""
        assert hasattr(PNBlockHeader, "IDOReadRequestHeader")
        assert PNBlockHeader.IDOReadRequestHeader == 0x0009
