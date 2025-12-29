"""Tests for profinet.util module."""

import pytest
from profinet.util import (
    s2mac,
    mac2s,
    s2ip,
    ip2s,
    to_hex,
    decode_bytes,
)
from profinet.exceptions import InvalidMACError, InvalidIPError


class TestMACConversion:
    """Test MAC address conversion functions."""

    def test_s2mac_valid(self):
        """Test valid MAC address string to bytes."""
        result = s2mac("01:02:03:04:05:06")
        assert result == b"\x01\x02\x03\x04\x05\x06"

    def test_s2mac_uppercase(self):
        """Test uppercase MAC address."""
        result = s2mac("AA:BB:CC:DD:EE:FF")
        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_s2mac_mixed_case(self):
        """Test mixed case MAC address."""
        result = s2mac("aA:Bb:cC:Dd:Ee:Ff")
        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_s2mac_invalid_format(self):
        """Test invalid MAC format raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("invalid-mac")

    def test_s2mac_empty(self):
        """Test empty MAC raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("")

    def test_s2mac_too_short(self):
        """Test too short MAC raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("01:02:03")

    def test_mac2s_valid(self):
        """Test valid bytes to MAC string."""
        result = mac2s(b"\x01\x02\x03\x04\x05\x06")
        assert result == "01:02:03:04:05:06"

    def test_mac2s_invalid_length(self):
        """Test invalid length raises exception."""
        with pytest.raises(InvalidMACError):
            mac2s(b"\x01\x02\x03")

    def test_mac_roundtrip(self):
        """Test MAC conversion roundtrip."""
        original = "de:ad:be:ef:ca:fe"
        assert mac2s(s2mac(original)) == original


class TestIPConversion:
    """Test IP address conversion functions."""

    def test_s2ip_valid(self):
        """Test valid bytes to IP string."""
        result = s2ip(b"\xc0\xa8\x01\x01")
        assert result == "192.168.1.1"

    def test_s2ip_zeros(self):
        """Test zero IP address."""
        result = s2ip(b"\x00\x00\x00\x00")
        assert result == "0.0.0.0"

    def test_s2ip_broadcast(self):
        """Test broadcast IP address."""
        result = s2ip(b"\xff\xff\xff\xff")
        assert result == "255.255.255.255"

    def test_s2ip_too_short(self):
        """Test too short bytes raises exception."""
        with pytest.raises(InvalidIPError):
            s2ip(b"\x01\x02")

    def test_ip2s_valid(self):
        """Test valid IP string to bytes."""
        result = ip2s("192.168.1.1")
        assert result == b"\xc0\xa8\x01\x01"

    def test_ip2s_zeros(self):
        """Test zero IP address."""
        result = ip2s("0.0.0.0")
        assert result == b"\x00\x00\x00\x00"

    def test_ip2s_invalid_format(self):
        """Test invalid IP format raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("invalid.ip")

    def test_ip2s_out_of_range(self):
        """Test out of range octet raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("256.1.1.1")

    def test_ip2s_empty(self):
        """Test empty IP raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("")

    def test_ip_roundtrip(self):
        """Test IP conversion roundtrip."""
        original = "10.20.30.40"
        assert s2ip(ip2s(original)) == original


class TestHelperFunctions:
    """Test helper utility functions."""

    def test_to_hex(self):
        """Test bytes to hex string."""
        result = to_hex(b"\x01\x02\x03")
        assert result == "01:02:03"

    def test_to_hex_empty(self):
        """Test empty bytes."""
        result = to_hex(b"")
        assert result == ""

    def test_decode_bytes(self):
        """Test bytes decoding with null stripping."""
        result = decode_bytes(b"hello\x00\x00")
        assert result == "hello"

    def test_decode_bytes_no_null(self):
        """Test bytes decoding without null."""
        result = decode_bytes(b"hello")
        assert result == "hello"
