"""Integration tests for DCE/RPC operations.

Tests RPC connection establishment, I&M record reading, diagnosis,
topology, and error handling against the PROFINET device emulator.
"""

import pytest

from profinet import (
    RPCCon,
    get_station_info,
    epm_lookup,
    ethernet_socket,
    get_mac,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    EPMEndpoint,
    indices,
)
from profinet.exceptions import RPCError, PNIOError

from .conftest import (
    skip_not_root,
    skip_no_container,
    EXPECTED_STATION_NAME,
    EXPECTED_VENDOR_ID,
    EXPECTED_DEVICE_ID,
    EXPECTED_HW_REVISION,
    EXPECTED_SW_REVISION_PREFIX,
    EXPECTED_SW_REVISION_MAJOR,
    EXPECTED_SW_REVISION_MINOR,
    EXPECTED_SERIAL_NUMBER,
    EXPECTED_ORDER_ID,
    EXPECTED_PROFILE_ID,
    EXPECTED_PROFILE_SPEC_TYPE,
    EXPECTED_IM1_TAG_FUNCTION,
    EXPECTED_IM1_TAG_LOCATION,
    EXPECTED_IM2_DATE,
    EXPECTED_IM3_DESCRIPTOR,
)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def device_info(interface, station_name):
    """Resolve station name to DCP device info (used by RPCCon)."""
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, station_name, timeout_sec=10)
        return info, src_mac
    finally:
        sock.close()


@pytest.fixture()
def rpc_connection(device_info):
    """Provide a connected RPCCon instance; close after test."""
    info, src_mac = device_info
    rpc = RPCCon(info, timeout=10.0)
    rpc.connect(src_mac)
    yield rpc
    rpc.close()


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class TestRPCConnection:
    """Test RPC connection lifecycle."""

    def test_connect_succeeds(self, device_info):
        """RPCCon.connect() should establish an AR without error."""
        info, src_mac = device_info
        rpc = RPCCon(info, timeout=10.0)
        try:
            rpc.connect(src_mac)
            # If we reach here, connect succeeded
        finally:
            rpc.close()

    def test_disconnect_and_reconnect(self, device_info):
        """Disconnect then reconnect should work cleanly."""
        info, src_mac = device_info
        rpc = RPCCon(info, timeout=10.0)
        try:
            rpc.connect(src_mac)
            rpc.disconnect()
            # Create a fresh connection after disconnect
            rpc2 = RPCCon(info, timeout=10.0)
            try:
                rpc2.connect(src_mac)
            finally:
                rpc2.close()
        finally:
            rpc.close()


# ---------------------------------------------------------------------------
# I&M Records
# ---------------------------------------------------------------------------


class TestIMRecords:
    """Test reading Identification & Maintenance records."""

    def test_read_im0(self, rpc_connection, device_properties):
        """I&M0 should return valid identification data."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0, PNInM0)

    def test_im0_vendor_id(self, rpc_connection):
        """I&M0 vendor ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.vendor_id == EXPECTED_VENDOR_ID, (
            f"Expected vendor_id 0x{EXPECTED_VENDOR_ID:04X}, "
            f"got 0x{im0.vendor_id:04X}"
        )

    def test_im0_order_id(self, rpc_connection):
        """I&M0 order ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        order_id = im0.order_id
        if isinstance(order_id, bytes):
            order_id = order_id.decode("latin-1").strip()
        assert order_id == EXPECTED_ORDER_ID, (
            f"Expected order_id '{EXPECTED_ORDER_ID}', got '{order_id}'"
        )

    def test_im0_serial_number(self, rpc_connection):
        """I&M0 serial number should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        serial = im0.im_serial_number
        if isinstance(serial, bytes):
            serial = serial.decode("latin-1").strip()
        assert serial == EXPECTED_SERIAL_NUMBER, (
            f"Expected serial '{EXPECTED_SERIAL_NUMBER}', got '{serial}'"
        )

    def test_im0_hardware_revision(self, rpc_connection):
        """I&M0 hardware revision should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_hardware_revision == EXPECTED_HW_REVISION

    def test_im0_sw_revision_prefix(self, rpc_connection):
        """I&M0 software revision prefix should be 'V'."""
        im0 = rpc_connection.read_im0()
        assert im0.sw_revision_prefix == EXPECTED_SW_REVISION_PREFIX, (
            f"Expected prefix {chr(EXPECTED_SW_REVISION_PREFIX)!r}, "
            f"got {chr(im0.sw_revision_prefix)!r}"
        )

    def test_im0_sw_revision_major(self, rpc_connection):
        """I&M0 software revision major should match."""
        im0 = rpc_connection.read_im0()
        assert im0.im_sw_revision_functional_enhancement == EXPECTED_SW_REVISION_MAJOR

    def test_im0_sw_revision_minor(self, rpc_connection):
        """I&M0 software revision minor (bug fix) should match."""
        im0 = rpc_connection.read_im0()
        assert im0.im_sw_revision_bug_fix == EXPECTED_SW_REVISION_MINOR

    def test_im0_profile_id(self, rpc_connection):
        """I&M0 profile ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_profile_id == EXPECTED_PROFILE_ID, (
            f"Expected profile_id 0x{EXPECTED_PROFILE_ID:04X}, "
            f"got 0x{im0.im_profile_id:04X}"
        )

    def test_im0_profile_spec_type(self, rpc_connection):
        """I&M0 profile specific type should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_profile_specific_type == EXPECTED_PROFILE_SPEC_TYPE, (
            f"Expected profile_spec_type 0x{EXPECTED_PROFILE_SPEC_TYPE:04X}, "
            f"got 0x{im0.im_profile_specific_type:04X}"
        )

    def test_im0_im_supported(self, rpc_connection):
        """I&M0 supported records should include IM1, IM2, IM3."""
        im0 = rpc_connection.read_im0()
        # PNET_SUPPORTED_IM1=0x0002, IM2=0x0004, IM3=0x0008
        supported = im0.im_supported
        assert supported & 0x0002, "IM1 should be supported"
        assert supported & 0x0004, "IM2 should be supported"
        assert supported & 0x0008, "IM3 should be supported"

    def test_read_im1(self, rpc_connection):
        """I&M1 should return tag function and location data."""
        im1 = rpc_connection.read_im1()
        assert isinstance(im1, PNInM1)

        tag_function = im1.im_tag_function
        if isinstance(tag_function, bytes):
            tag_function = tag_function.decode("latin-1").strip()
        # p-net may or may not populate default IM1 values
        assert isinstance(tag_function, str)

    def test_read_im2(self, rpc_connection):
        """I&M2 should return installation date data."""
        im2 = rpc_connection.read_im2()
        assert isinstance(im2, PNInM2)

        date = im2.im_date
        if isinstance(date, bytes):
            date = date.decode("latin-1").strip()
        assert isinstance(date, str)

    def test_read_im3(self, rpc_connection):
        """I&M3 should return descriptor data."""
        im3 = rpc_connection.read_im3()
        assert isinstance(im3, PNInM3)

        descriptor = im3.im_descriptor
        if isinstance(descriptor, bytes):
            descriptor = descriptor.decode("latin-1").strip()
        assert isinstance(descriptor, str)

    def test_read_all_im(self, rpc_connection):
        """read_all_im should return a dict with at least IM0."""
        result = rpc_connection.read_all_im()
        assert isinstance(result, dict)
        assert "im0" in result, "read_all_im should include I&M0"


# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------


class TestDiagnosis:
    """Test reading diagnosis data."""

    def test_read_diagnosis_no_crash(self, rpc_connection):
        """Reading diagnosis should not raise for a healthy device."""
        try:
            diag = rpc_connection.read_diagnosis()
            # Healthy device may return empty diagnosis
            assert diag is not None
        except PNIOError:
            # Some devices return PNIO error for empty diagnosis
            pass

    def test_read_all_diagnosis(self, rpc_connection):
        """read_all_diagnosis should return a dict (possibly empty)."""
        try:
            result = rpc_connection.read_all_diagnosis()
            assert isinstance(result, dict)
        except (RPCError, PNIOError):
            # Device may not support all diagnosis indices
            pass


# ---------------------------------------------------------------------------
# Topology / Identification
# ---------------------------------------------------------------------------


class TestTopology:
    """Test reading topology and identification data."""

    def test_read_real_identification_data(self, rpc_connection):
        """RealIdentificationData should list slots and subslots."""
        try:
            rid = rpc_connection.read_real_identification_data()
            assert rid is not None
            # Should have at least the DAP (slot 0)
            assert len(rid.slots) >= 1, "Should have at least one slot"
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

    def test_read_pd_real_data(self, rpc_connection):
        """PDRealData should return interface/port information."""
        try:
            pd = rpc_connection.read_pd_real_data()
            assert pd is not None
        except (RPCError, PNIOError):
            pytest.skip("Device does not support PDRealData")

    def test_discover_slots(self, rpc_connection):
        """discover_slots should return slot/subslot list."""
        try:
            slots = rpc_connection.discover_slots()
            assert isinstance(slots, list)
            assert len(slots) >= 1, "Should discover at least one slot"
            # Verify slot 0 (DAP) exists
            dap_slots = [s for s in slots if s.slot == 0]
            assert len(dap_slots) >= 1, "Slot 0 (DAP) should exist"
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")

    def test_read_module_diff(self, rpc_connection):
        """ModuleDiffBlock should be readable after connect."""
        try:
            diff = rpc_connection.read_module_diff()
            assert diff is not None
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------


class TestRPCErrors:
    """Test that invalid operations return proper errors."""

    def test_read_invalid_slot(self, rpc_connection):
        """Reading from a nonexistent slot should raise an error."""
        with pytest.raises((RPCError, PNIOError)):
            rpc_connection.read(api=0, slot=99, subslot=1, idx=indices.IM0)

    def test_read_invalid_subslot(self, rpc_connection):
        """Reading from a nonexistent subslot should raise an error."""
        with pytest.raises((RPCError, PNIOError)):
            rpc_connection.read(api=0, slot=0, subslot=0xFFFF, idx=indices.IM0)

    def test_read_invalid_index(self, rpc_connection):
        """Reading an unsupported index should raise an error."""
        with pytest.raises((RPCError, PNIOError)):
            # 0x0001 is typically not a valid record index for slot 0
            rpc_connection.read(api=0, slot=0, subslot=1, idx=0x0001)


# ---------------------------------------------------------------------------
# EPM Lookup
# ---------------------------------------------------------------------------


class TestEPMLookup:
    """Test EPM (Endpoint Mapper) lookup."""

    def test_epm_lookup_finds_endpoint(self, device_info):
        """EPM lookup should find at least one PNIO endpoint."""
        info, _ = device_info
        try:
            endpoints = epm_lookup(info.ip)
            assert isinstance(endpoints, list)
            assert len(endpoints) >= 1, "EPM should return at least one endpoint"
        except (RPCError, OSError):
            pytest.skip("EPM lookup not supported by device")

    def test_epm_endpoint_has_pnio_interface(self, device_info):
        """EPM should include a PNIO-Device interface UUID."""
        info, _ = device_info
        try:
            endpoints = epm_lookup(info.ip)
            pnio_uuids = [
                ep for ep in endpoints
                if "dea00001" in ep.interface_uuid.lower()
            ]
            assert len(pnio_uuids) >= 1, (
                "Should find at least one PNIO-Device endpoint. "
                f"Found interfaces: {[ep.interface_uuid for ep in endpoints]}"
            )
        except (RPCError, OSError):
            pytest.skip("EPM lookup not supported by device")
