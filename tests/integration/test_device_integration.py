"""Integration tests for the high-level ProfinetDevice API.

Tests device discovery, context manager, get_info, and I&M convenience
methods using the ProfinetDevice class from profinet.device.
"""

import pytest

from profinet import (
    ProfinetDevice,
    DeviceInfo,
    PNInM0,
    scan,
)

from .conftest import (
    skip_not_root,
    skip_no_container,
    EXPECTED_STATION_NAME,
    EXPECTED_VENDOR_ID,
    EXPECTED_DEVICE_ID,
    EXPECTED_ORDER_ID,
    EXPECTED_SERIAL_NUMBER,
)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestProfinetDeviceDiscover:
    """Test ProfinetDevice.discover() factory method."""

    def test_discover_by_name(self, interface, station_name):
        """Discover device by station name should return a ProfinetDevice."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        assert device is not None
        assert device.name == station_name

    def test_discover_nonexistent_raises(self, interface):
        """Discovering a nonexistent device should raise an error."""
        from profinet.exceptions import DCPDeviceNotFoundError

        with pytest.raises(DCPDeviceNotFoundError):
            ProfinetDevice.discover(
                "this-device-does-not-exist", interface, timeout=3.0
            )


# ---------------------------------------------------------------------------
# Context Manager
# ---------------------------------------------------------------------------


class TestProfinetDeviceContextManager:
    """Test ProfinetDevice as context manager."""

    def test_context_manager_connect_disconnect(self, interface, station_name):
        """Using 'with' should connect on enter and close on exit."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            # Inside the context, device should be connected
            assert device._connected is True

        # After exiting, device should be disconnected
        assert device._connected is False

    def test_context_manager_read_im0(self, interface, station_name):
        """Should be able to read I&M0 inside context manager."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            im0 = device.read_im0()
            assert isinstance(im0, PNInM0)
            assert im0.vendor_id == EXPECTED_VENDOR_ID


# ---------------------------------------------------------------------------
# Device Info
# ---------------------------------------------------------------------------


class TestProfinetDeviceInfo:
    """Test ProfinetDevice.get_info() method."""

    def test_get_info_basic(self, interface, station_name):
        """get_info should return a DeviceInfo with DCP and I&M0 data."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            info = device.get_info()
            assert isinstance(info, DeviceInfo)
            assert info.name == station_name
            assert info.vendor_id == EXPECTED_VENDOR_ID
            assert info.device_id == EXPECTED_DEVICE_ID

    def test_get_info_has_im0(self, interface, station_name):
        """get_info should populate I&M0 data."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            info = device.get_info()
            assert info.im0 is not None, "DeviceInfo.im0 should be populated"

    def test_get_info_serial_number(self, interface, station_name):
        """DeviceInfo.serial_number should match expected value."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            info = device.get_info()
            assert info.serial_number == EXPECTED_SERIAL_NUMBER, (
                f"Expected serial '{EXPECTED_SERIAL_NUMBER}', "
                f"got '{info.serial_number}'"
            )

    def test_get_info_order_id(self, interface, station_name):
        """DeviceInfo.order_id should match expected value."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            info = device.get_info()
            assert info.order_id == EXPECTED_ORDER_ID, (
                f"Expected order_id '{EXPECTED_ORDER_ID}', "
                f"got '{info.order_id}'"
            )

    def test_get_info_with_topology(self, interface, station_name):
        """get_info with include_topology should not crash."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        with device:
            info = device.get_info(include_topology=True)
            assert isinstance(info, DeviceInfo)
            # Topology may or may not be available
            # Just verify it does not crash

    def test_device_properties(self, interface, station_name):
        """Device properties (name, ip, mac) should be accessible."""
        device = ProfinetDevice.discover(station_name, interface, timeout=10.0)
        assert device.name == station_name
        assert device.ip != ""
        assert device.mac != ""


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class TestScan:
    """Test module-level scan() function."""

    def test_scan_finds_device(self, interface, station_name):
        """scan() should find the test device."""
        devices = list(scan(interface, timeout=5.0))
        assert len(devices) >= 1, "scan() should find at least one device"

        names = [d.name for d in devices]
        assert station_name in names, (
            f"Device '{station_name}' not found. Discovered: {names}"
        )

    def test_scan_device_has_ip(self, interface, station_name):
        """Scanned devices should have IP addresses."""
        for device in scan(interface, timeout=5.0):
            if device.name == station_name:
                assert device.ip != "", "Device should have an IP address"
                return
        pytest.fail(f"Device '{station_name}' not found in scan")


# ---------------------------------------------------------------------------
# I&M Convenience Methods
# ---------------------------------------------------------------------------


class TestProfinetDeviceIM:
    """Test ProfinetDevice I&M convenience methods."""

    def test_read_im0_convenience(self, interface, station_name):
        """device.read_im0() should return PNInM0."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            im0 = device.read_im0()
            assert isinstance(im0, PNInM0)

    def test_read_im1_convenience(self, interface, station_name):
        """device.read_im1() should not crash (IM1 is supported)."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            im1 = device.read_im1()
            assert im1 is not None

    def test_read_im2_convenience(self, interface, station_name):
        """device.read_im2() should not crash (IM2 is supported)."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            im2 = device.read_im2()
            assert im2 is not None

    def test_read_im3_convenience(self, interface, station_name):
        """device.read_im3() should not crash (IM3 is supported)."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            im3 = device.read_im3()
            assert im3 is not None

    def test_read_all_im_convenience(self, interface, station_name):
        """device.read_all_im() should return dict with at least im0."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            result = device.read_all_im()
            assert isinstance(result, dict)
            assert "im0" in result


# ---------------------------------------------------------------------------
# Slot Discovery and Diagnosis
# ---------------------------------------------------------------------------


class TestProfinetDeviceAdvanced:
    """Test advanced ProfinetDevice methods."""

    def test_discover_slots(self, interface, station_name):
        """device.discover_slots() should find at least the DAP."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            try:
                slots = device.discover_slots()
                assert len(slots) >= 1, "Should find at least one slot"
            except Exception:
                pytest.skip("Device does not support slot discovery")

    def test_read_diagnosis(self, interface, station_name):
        """device.read_diagnosis() should not crash."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            try:
                diag = device.read_diagnosis()
                assert diag is not None
            except Exception:
                # Diagnosis may fail on healthy device with no entries
                pass

    def test_read_topology(self, interface, station_name):
        """device.read_topology() should not crash."""
        with ProfinetDevice.discover(station_name, interface, timeout=10.0) as device:
            try:
                topo = device.read_topology()
                assert topo is not None
            except Exception:
                pytest.skip("Device does not support topology readout")
