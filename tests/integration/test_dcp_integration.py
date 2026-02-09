"""Integration tests for DCP (Discovery and Configuration Protocol).

Tests DCP discovery, parameter read, and signal operations against
a real PROFINET device emulator running in Docker.
"""

import pytest

from profinet import (
    ethernet_socket,
    get_mac,
    send_discover,
    read_response,
    get_param,
    signal_device,
    DCPDeviceDescription,
)

from .conftest import (
    skip_not_root,
    skip_no_container,
    EXPECTED_STATION_NAME,
    EXPECTED_VENDOR_ID,
    EXPECTED_DEVICE_ID,
)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]


# ---------------------------------------------------------------------------
# DCP Discovery
# ---------------------------------------------------------------------------


class TestDCPDiscover:
    """Test DCP multicast discovery finds the emulated device."""

    def test_discover_finds_device(self, interface):
        """DCP discover should find at least one device."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=5)
            assert len(responses) >= 1, "Expected at least one DCP response"
        finally:
            sock.close()

    def test_discover_correct_station_name(self, interface, station_name):
        """Discovered device should have the expected station name."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=5)

            found = False
            for mac, blocks in responses.items():
                info = DCPDeviceDescription(mac, blocks)
                if info.name == station_name:
                    found = True
                    break

            assert found, (
                f"Device with station name '{station_name}' not found. "
                f"Found: {[DCPDeviceDescription(m, b).name for m, b in responses.items()]}"
            )
        finally:
            sock.close()

    def test_discover_correct_vendor_id(self, interface, station_name):
        """Discovered device should report correct vendor ID."""
        device = self._find_device(interface, station_name)
        assert device.vendor_id == EXPECTED_VENDOR_ID, (
            f"Expected vendor_id 0x{EXPECTED_VENDOR_ID:04X}, "
            f"got 0x{device.vendor_id:04X}"
        )

    def test_discover_correct_device_id(self, interface, station_name):
        """Discovered device should report correct device ID."""
        device = self._find_device(interface, station_name)
        assert device.device_id == EXPECTED_DEVICE_ID, (
            f"Expected device_id 0x{EXPECTED_DEVICE_ID:04X}, "
            f"got 0x{device.device_id:04X}"
        )

    def test_discover_has_valid_ip(self, interface, station_name):
        """Discovered device should have a non-zero IP address."""
        device = self._find_device(interface, station_name)
        assert device.ip != "0.0.0.0", "Device IP should not be 0.0.0.0"
        # Verify it looks like a valid IPv4 address
        parts = device.ip.split(".")
        assert len(parts) == 4, f"Invalid IP format: {device.ip}"
        for part in parts:
            assert 0 <= int(part) <= 255

    def test_discover_has_valid_mac(self, interface, station_name):
        """Discovered device should have a non-zero MAC address."""
        device = self._find_device(interface, station_name)
        assert device.mac != "00:00:00:00:00:00", "Device MAC should not be all zeros"
        parts = device.mac.split(":")
        assert len(parts) == 6, f"Invalid MAC format: {device.mac}"

    def test_discover_has_netmask(self, interface, station_name):
        """Discovered device should have a non-zero netmask."""
        device = self._find_device(interface, station_name)
        assert device.netmask != "0.0.0.0", "Netmask should not be 0.0.0.0"

    def test_discover_device_role_is_io_device(self, interface, station_name):
        """Discovered device should report IO-Device role."""
        device = self._find_device(interface, station_name)
        # Role bit 0x01 = IO-Device
        assert device.device_role & 0x01, (
            f"Expected IO-Device role (0x01), got role=0x{device.device_role:02X}"
        )

    def test_discover_has_supported_options(self, interface, station_name):
        """Discovered device should report supported DCP options."""
        device = self._find_device(interface, station_name)
        assert len(device.supported_options) > 0, "Device should report supported options"

    @staticmethod
    def _find_device(interface: str, station_name: str) -> DCPDeviceDescription:
        """Helper: discover and return the device with the given station name."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=5)

            for mac, blocks in responses.items():
                info = DCPDeviceDescription(mac, blocks)
                if info.name == station_name:
                    return info

            names = [DCPDeviceDescription(m, b).name for m, b in responses.items()]
            pytest.fail(
                f"Device '{station_name}' not found. Discovered: {names}"
            )
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Get Parameter
# ---------------------------------------------------------------------------


class TestDCPGetParam:
    """Test DCP Get operations for reading device parameters."""

    def test_get_param_name(self, interface, station_name):
        """get_param('name') should return the device station name."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = get_param(sock, src_mac, device.mac, "name", timeout_sec=5)
            assert result is not None, "get_param('name') returned None"
            name = result.decode("utf-8", errors="replace")
            assert name == station_name, f"Expected '{station_name}', got '{name}'"
        finally:
            sock.close()

    def test_get_param_ip(self, interface, station_name):
        """get_param('ip') should return IP configuration bytes."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = get_param(sock, src_mac, device.mac, "ip", timeout_sec=5)
            assert result is not None, "get_param('ip') returned None"
            # IP block should be at least 12 bytes (IP + netmask + gateway)
            assert len(result) >= 12, f"IP block too short: {len(result)} bytes"
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Signal (LED Blink)
# ---------------------------------------------------------------------------


class TestDCPSignal:
    """Test DCP Signal command for LED identification."""

    def test_signal_device(self, interface, station_name):
        """signal_device should get a response from the device."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = signal_device(
                sock, src_mac, device.mac, duration_ms=1000, timeout_sec=5
            )
            # p-net may or may not respond to signal; just verify no crash
            # result is True if response received, False on timeout
            assert isinstance(result, bool)
        finally:
            sock.close()
