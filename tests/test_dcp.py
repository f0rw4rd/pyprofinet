"""Tests for profinet.dcp module."""

import pytest
from profinet.dcp import DCPDeviceDescription, PARAMS
from profinet.protocol import PNDCPBlock


class TestDCPDeviceDescription:
    """Test DCPDeviceDescription class."""

    def test_basic_creation(self):
        """Test creating device with minimal data."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\xc0\xa8\x01\xfe",
            PNDCPBlock.DEVICE_ID: b"\x00\x2a\x00\x01",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.mac == "00:11:22:33:44:55"
        assert device.name == "test-device"
        assert device.ip == "192.168.1.1"
        assert device.netmask == "255.255.255.0"
        assert device.gateway == "192.168.1.254"
        assert device.vendor_id == 0x002a
        assert device.device_id == 0x0001

    def test_missing_name(self):
        """Test device with missing name block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.name == ""

    def test_missing_ip(self):
        """Test device with missing IP block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.ip == "0.0.0.0"
        assert device.netmask == "0.0.0.0"
        assert device.gateway == "0.0.0.0"

    def test_missing_device_id(self):
        """Test device with missing device ID block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.vendor_id == 0
        assert device.device_id == 0

    def test_vendor_id_property(self):
        """Test vendor_id property calculation."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ID: b"\x02\xb8\x00\x42",  # Vendor 0x02B8, Device 0x0042
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.vendor_id == 0x02b8
        assert device.device_id == 0x0042

    def test_repr(self):
        """Test string representation."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"my-device",
            PNDCPBlock.IP_ADDRESS: b"\x0a\x00\x00\x01" + b"\xff\x00\x00\x00" + b"\x0a\x00\x00\xfe",
        }

        device = DCPDeviceDescription(mac, blocks)

        repr_str = repr(device)
        assert "my-device" in repr_str
        assert "10.0.0.1" in repr_str

    def test_str(self):
        """Test string output."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"my-device",
            PNDCPBlock.IP_ADDRESS: b"\x0a\x00\x00\x01" + b"\xff\x00\x00\x00" + b"\x0a\x00\x00\xfe",
        }

        device = DCPDeviceDescription(mac, blocks)

        str_output = str(device)
        assert "PROFINET Device" in str_output
        assert "my-device" in str_output


class TestPARAMS:
    """Test PARAMS constant."""

    def test_name_param(self):
        """Test name parameter mapping."""
        assert "name" in PARAMS
        assert PARAMS["name"] == PNDCPBlock.NAME_OF_STATION

    def test_ip_param(self):
        """Test IP parameter mapping."""
        assert "ip" in PARAMS
        assert PARAMS["ip"] == PNDCPBlock.IP_ADDRESS


from unittest.mock import MagicMock, patch
from struct import pack

from profinet.dcp import (
    send_discover,
    send_request,
    read_response,
    get_param,
    set_param,
    signal_device,
    reset_to_factory,
    RESET_MODE_COMMUNICATION,
    RESET_MODE_APPLICATION,
    RESET_MODE_FACTORY,
    DCP_MULTICAST_MAC,
    _generate_xid,
)
from profinet.exceptions import DCPError


class TestGenerateXid:
    """Test XID generation."""

    def test_generate_xid_returns_int(self):
        """Test _generate_xid returns an integer."""
        xid = _generate_xid()
        assert isinstance(xid, int)
        assert 0 <= xid <= 0xFFFFFFFF

    def test_generate_xid_different_values(self):
        """Test _generate_xid returns different values."""
        xids = [_generate_xid() for _ in range(10)]
        # Most values should be unique (with very high probability)
        assert len(set(xids)) > 5


class TestSendDiscover:
    """Test send_discover function."""

    def test_send_discover_sends_packet(self):
        """Test send_discover sends packet via socket."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"

        send_discover(mock_sock, src_mac)

        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert len(sent_data) > 20  # Has Ethernet + DCP headers


class TestSendRequest:
    """Test send_request function."""

    def test_send_request_sends_packet(self):
        """Test send_request sends filtered request."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"

        send_request(mock_sock, src_mac, PNDCPBlock.NAME_OF_STATION, b"test-device")

        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert b"test-device" in sent_data


class TestReadResponse:
    """Test read_response function."""

    def test_read_response_empty_on_no_data(self):
        """Test read_response returns empty dict when no data."""
        mock_sock = MagicMock()
        from socket import timeout as SocketTimeout
        mock_sock.recv.side_effect = SocketTimeout()

        result = read_response(mock_sock, b"\x00\x11\x22\x33\x44\x55", timeout_sec=1)

        assert result == {}



class TestGetParam:
    """Test get_param function."""

    def test_get_param_invalid_param(self):
        """Test get_param raises error for invalid parameter."""
        mock_sock = MagicMock()

        with pytest.raises(DCPError, match="Unknown parameter"):
            get_param(mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "invalid")

    def test_get_param_sends_request(self):
        """Test get_param sends request and reads response."""
        mock_sock = MagicMock()
        from socket import timeout as SocketTimeout
        mock_sock.recv.side_effect = SocketTimeout()

        result = get_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            timeout_sec=1
        )

        mock_sock.send.assert_called_once()
        assert result is None  # No response received


class TestSetParam:
    """Test set_param function."""

    def test_set_param_invalid_param(self):
        """Test set_param raises error for invalid parameter."""
        mock_sock = MagicMock()

        with pytest.raises(DCPError, match="Unknown parameter"):
            set_param(mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "invalid", "value")

    def test_set_param_sends_request(self):
        """Test set_param sends request."""
        mock_sock = MagicMock()
        from socket import timeout as SocketTimeout
        mock_sock.recv.side_effect = SocketTimeout()

        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            "new-name",
            timeout_sec=1
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response received


class TestSignalDevice:
    """Test signal_device function."""

    def test_signal_device_sends_request(self):
        """Test signal_device sends Control/Signal request."""
        mock_sock = MagicMock()
        from socket import timeout as SocketTimeout
        mock_sock.recv.side_effect = SocketTimeout()

        result = signal_device(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            duration_ms=5000,
            timeout_sec=1
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response

    def test_signal_device_success(self):
        """Test signal_device returns True on response."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00" * 100  # Fake response

        result = signal_device(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            timeout_sec=1
        )

        assert result is True


class TestResetToFactory:
    """Test reset_to_factory function."""

    def test_reset_to_factory_sends_request(self):
        """Test reset_to_factory sends Control/ResetToFactory request."""
        mock_sock = MagicMock()
        from socket import timeout as SocketTimeout
        mock_sock.recv.side_effect = SocketTimeout()

        result = reset_to_factory(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            mode=RESET_MODE_COMMUNICATION,
            timeout_sec=1
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response

    def test_reset_to_factory_success(self):
        """Test reset_to_factory returns True on response."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00" * 100  # Fake response

        result = reset_to_factory(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            mode=RESET_MODE_COMMUNICATION,
            timeout_sec=1
        )

        assert result is True

    def test_reset_modes_defined(self):
        """Test reset mode constants are defined correctly."""
        assert RESET_MODE_COMMUNICATION == 0x0002
        assert RESET_MODE_APPLICATION == 0x0004
        assert RESET_MODE_FACTORY == 0x0040


class TestConstants:
    """Test DCP constants."""

    def test_multicast_address(self):
        """Test DCP multicast address constant."""
        assert DCP_MULTICAST_MAC == "01:0e:cf:00:00:00"
