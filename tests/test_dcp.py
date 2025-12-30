"""Tests for profinet.dcp module."""

import pytest
from profinet.dcp import (
    DCPDeviceDescription,
    PARAMS,
    decode_device_role,
    get_block_name,
    DEVICE_ROLE_IO_DEVICE,
    DEVICE_ROLE_IO_CONTROLLER,
    DEVICE_ROLE_IO_MULTIDEVICE,
    DEVICE_ROLE_PN_SUPERVISOR,
    DCP_OPTION_IP,
    DCP_OPTION_DEVICE,
    DCP_SUBOPTION_DEVICE_TYPE,
    DCP_SUBOPTION_DEVICE_ROLE,
    DCP_SUBOPTION_DEVICE_INSTANCE,
    DCP_SUBOPTION_DEVICE_OPTIONS,
    DCP_SUBOPTION_DEVICE_ALIAS,
)
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

    def test_device_type_parsing(self):
        """Test device type block parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.DEVICE_TYPE: b"S7-1200",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_type == "S7-1200"

    def test_device_type_with_null_terminator(self):
        """Test device type with null bytes stripped."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_TYPE: b"ET 200SP\x00\x00\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_type == "ET 200SP"

    def test_device_role_io_device(self):
        """Test device role parsing for IO-Device."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x01\x00",  # IO-Device
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x01
        assert "IO-Device" in device.device_roles

    def test_device_role_io_controller(self):
        """Test device role parsing for IO-Controller."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x02\x00",  # IO-Controller
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x02
        assert "IO-Controller" in device.device_roles

    def test_device_role_combined(self):
        """Test device role with multiple roles."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x03\x00",  # IO-Device + IO-Controller
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x03
        assert "IO-Device" in device.device_roles
        assert "IO-Controller" in device.device_roles

    def test_device_instance(self):
        """Test device instance parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_INSTANCE: b"\x00\x64",  # Instance 0.100
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_instance == (0, 100)

    def test_device_alias(self):
        """Test device alias name parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ALIAS: b"port-001.plc-main\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.alias_name == "port-001.plc-main"

    def test_supported_options(self):
        """Test supported options parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        # Options block: (opt, subopt) pairs
        blocks = {
            PNDCPBlock.DEVICE_OPTIONS: b"\x01\x02\x02\x01\x02\x03",  # IP/IP, Dev/Type, Dev/DeviceID
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (1, 2) in device.supported_options  # IP/IP
        assert (2, 1) in device.supported_options  # Device/Type
        assert (2, 3) in device.supported_options  # Device/DeviceID

    def test_raw_blocks_unknown_option(self):
        """Test unknown blocks are stored in raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x80, 0x01): b"\xde\xad\xbe\xef",  # Vendor-specific block
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (0x80, 0x01) in device.raw_blocks
        assert device.raw_blocks[(0x80, 0x01)] == b"\xde\xad\xbe\xef"

    def test_raw_blocks_not_include_known(self):
        """Test known blocks are not in raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00",
            PNDCPBlock.DEVICE_TYPE: b"S7-1500",
        }

        device = DCPDeviceDescription(mac, blocks)

        # Known blocks should not be in raw_blocks
        assert PNDCPBlock.NAME_OF_STATION not in device.raw_blocks
        assert PNDCPBlock.IP_ADDRESS not in device.raw_blocks
        assert PNDCPBlock.DEVICE_TYPE not in device.raw_blocks

    def test_str_with_unknown_blocks(self):
        """Test string output includes unknown blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x80, 0x01): b"\xde\xad",  # Vendor-specific
        }

        device = DCPDeviceDescription(mac, blocks)
        str_output = str(device)

        assert "Unknown (128,1)" in str_output
        assert "dead" in str_output

    def test_full_siemens_device(self):
        """Test parsing realistic Siemens S7-1200 response."""
        mac = b"\x28\x63\x36\x80\xb1\xf4"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"plcxb1d0ed",
            PNDCPBlock.DEVICE_TYPE: b"S7-1200",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x00\xd7" + b"\xff\xff\xff\x00" + b"\xc0\xa8\x00\x01",
            PNDCPBlock.DEVICE_ID: b"\x00\x2a\x01\x0d",  # Siemens, S7-1200
            PNDCPBlock.DEVICE_ROLE: b"\x02\x00",  # IO-Controller
            PNDCPBlock.DEVICE_INSTANCE: b"\x00\x64",  # 0.100
            PNDCPBlock.DEVICE_OPTIONS: b"\x02\x07",  # Device/Instance
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.mac == "28:63:36:80:b1:f4"
        assert device.name == "plcxb1d0ed"
        assert device.device_type == "S7-1200"
        assert device.ip == "192.168.0.215"
        assert device.vendor_id == 0x002a
        assert device.device_id == 0x010d
        assert "IO-Controller" in device.device_roles
        assert device.device_instance == (0, 100)


class TestDecodeDeviceRole:
    """Test decode_device_role function."""

    def test_io_device(self):
        """Test IO-Device role."""
        roles = decode_device_role(DEVICE_ROLE_IO_DEVICE)
        assert roles == ["IO-Device"]

    def test_io_controller(self):
        """Test IO-Controller role."""
        roles = decode_device_role(DEVICE_ROLE_IO_CONTROLLER)
        assert roles == ["IO-Controller"]

    def test_io_multidevice(self):
        """Test IO-Multidevice role."""
        roles = decode_device_role(DEVICE_ROLE_IO_MULTIDEVICE)
        assert roles == ["IO-Multidevice"]

    def test_pn_supervisor(self):
        """Test PN-Supervisor role."""
        roles = decode_device_role(DEVICE_ROLE_PN_SUPERVISOR)
        assert roles == ["PN-Supervisor"]

    def test_combined_roles(self):
        """Test combined roles."""
        roles = decode_device_role(0x03)  # IO-Device + IO-Controller
        assert "IO-Device" in roles
        assert "IO-Controller" in roles
        assert len(roles) == 2

    def test_all_roles(self):
        """Test all roles combined."""
        roles = decode_device_role(0x0F)  # All 4 roles
        assert len(roles) == 4

    def test_unknown_role(self):
        """Test unknown role returns Unknown."""
        roles = decode_device_role(0x00)
        assert roles == ["Unknown"]


class TestGetBlockName:
    """Test get_block_name function."""

    def test_ip_option(self):
        """Test IP option names."""
        assert get_block_name(0x01, 0x01) == "IP/MAC"
        assert get_block_name(0x01, 0x02) == "IP/IP"
        assert get_block_name(0x01, 0x03) == "IP/FullIPSuite"

    def test_device_option(self):
        """Test Device option names."""
        assert get_block_name(0x02, 0x01) == "Device/Type"
        assert get_block_name(0x02, 0x02) == "Device/Name"
        assert get_block_name(0x02, 0x03) == "Device/DeviceID"
        assert get_block_name(0x02, 0x04) == "Device/Role"
        assert get_block_name(0x02, 0x05) == "Device/Options"
        assert get_block_name(0x02, 0x07) == "Device/Instance"

    def test_control_option(self):
        """Test Control option names."""
        assert get_block_name(0x05, 0x01) == "Control/Start"
        assert get_block_name(0x05, 0x03) == "Control/Signal"
        assert get_block_name(0x05, 0x06) == "Control/ResetToFactory"

    def test_vendor_option(self):
        """Test vendor-specific option range."""
        name = get_block_name(0x80, 0x01)
        assert "Vendor-0x80" in name

        name = get_block_name(0xFE, 0x05)
        assert "Vendor-0xFE" in name

    def test_unknown_option(self):
        """Test unknown option."""
        name = get_block_name(0x10, 0x99)
        assert "Opt-0x10" in name
        assert "0x99" in name

    def test_unknown_suboption(self):
        """Test known option with unknown suboption."""
        name = get_block_name(0x02, 0xFF)
        assert "Device/" in name
        assert "0xFF" in name


class TestDeviceRoleConstants:
    """Test device role constants."""

    def test_io_device_value(self):
        """Test IO-Device constant."""
        assert DEVICE_ROLE_IO_DEVICE == 0x01

    def test_io_controller_value(self):
        """Test IO-Controller constant."""
        assert DEVICE_ROLE_IO_CONTROLLER == 0x02

    def test_io_multidevice_value(self):
        """Test IO-Multidevice constant."""
        assert DEVICE_ROLE_IO_MULTIDEVICE == 0x04

    def test_pn_supervisor_value(self):
        """Test PN-Supervisor constant."""
        assert DEVICE_ROLE_PN_SUPERVISOR == 0x08


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
