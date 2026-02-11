"""Integration tests for cyclic IO exchange.

Tests the full PROFINET cyclic IO lifecycle against the p-net container:
1. Connect with IOCARSingle + IOCR + AlarmCR + ExpectedSubmodule
2. PrmEnd (end parameter phase)
3. ApplicationReady (wait for device CControl, respond with DONE)
4. Start CyclicController (TX/RX threads)
5. Cyclic data exchange
6. Stop and disconnect
"""

import logging
import time

import pytest

from profinet import (
    ConnectResult,
    IOCRSetup,
    IOSlot,
    RPCCon,
    ethernet_socket,
    get_mac,
    get_station_info,
)
from profinet.cyclic import CyclicController
from profinet.rt import (
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOCRConfig,
    IODataObject,
)

from .conftest import (
    GSDML_MOD_ECHO,
    GSDML_SUBMOD_ECHO,
    skip_no_container,
    skip_not_root,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]

# Cycle time: 128ms (conservative for Python + container)
SEND_CLOCK_FACTOR = 32  # 1ms base
REDUCTION_RATIO = 128  # 128ms cycle
WATCHDOG_FACTOR = 10  # 10 * 128ms = 1.28s watchdog
DATA_HOLD_FACTOR = 10

# Echo module: slot 4, subslot 1, 8B input + 8B output
ECHO_SLOT = 4
ECHO_SUBSLOT = 1
ECHO_INPUT_LEN = 8
ECHO_OUTPUT_LEN = 8

# Cyclic test duration
RUN_DURATION = 5  # seconds


# ---------------------------------------------------------------------------
# Helper: build IOCRConfig objects matching _build_iocr_block frame layout
# ---------------------------------------------------------------------------


def build_iocr_configs(iocr_slots, input_frame_id, output_frame_id):
    """Build IOCRConfig objects for CyclicController.

    Computes frame offsets matching what RPCCon._build_iocr_block builds,
    including IOCS entries for submodules without data in each direction.

    Returns:
        (input_iocr, output_iocr, output_iocs_offsets)
        where output_iocs_offsets is a list of (slot, subslot, offset)
        for manual IOCS setting in the output frame.
    """
    # Input IOCR: device -> controller
    input_objects = []
    frame_offset = 0
    for s in iocr_slots:
        if s.input_length > 0:
            input_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=frame_offset,
                    data_length=s.input_length,
                    iops_offset=frame_offset + s.input_length,
                )
            )
            frame_offset += s.input_length + 1  # data + IOPS

    # IOCS entries for slots with no input data
    for s in iocr_slots:
        if s.input_length == 0:
            frame_offset += 1

    input_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_INPUT,
        iocr_reference=1,
        frame_id=input_frame_id,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_length=max(40, frame_offset),
        objects=input_objects,
    )

    # Output IOCR: controller -> device
    output_objects = []
    frame_offset = 0
    for s in iocr_slots:
        if s.output_length > 0:
            output_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=frame_offset,
                    data_length=s.output_length,
                    iops_offset=frame_offset + s.output_length,
                )
            )
            frame_offset += s.output_length + 1  # data + IOPS

    # IOCS entries for slots with no output data
    output_iocs_offsets = []
    for s in iocr_slots:
        if s.output_length == 0:
            output_iocs_offsets.append((s.slot, s.subslot, frame_offset))
            frame_offset += 1

    output_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=2,
        frame_id=output_frame_id,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_length=max(40, frame_offset),
        objects=output_objects,
    )

    return input_iocr, output_iocr, output_iocs_offsets


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def device_info(interface, station_name):
    """Resolve station name to DCP device info."""
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, station_name, timeout_sec=3)
        return info, src_mac
    finally:
        sock.close()


@pytest.fixture(scope="module")
def dap_slot_info(device_info):
    """Discover DAP module/submodule IDs from device.

    Returns dict mapping subslot -> (module_ident, submodule_ident) for slot 0.
    """
    info, src_mac = device_info
    rpc = RPCCon(info, timeout=5.0)
    rpc.connect(src_mac)
    try:
        slots = rpc.discover_slots()
        dap = {}
        for s in slots:
            if s.slot == 0:
                dap[s.subslot] = (s.module_ident, s.submodule_ident)
        assert 1 in dap, "DAP subslot 1 not found"
        assert 0x8000 in dap, "DAP interface subslot 0x8000 not found"
        assert 0x8001 in dap, "DAP port subslot 0x8001 not found"
        return dap
    finally:
        rpc.close()
        time.sleep(2)  # Let device release AR before cyclic connect


@pytest.fixture(scope="module")
def iocr_setup(dap_slot_info):
    """Build IOCRSetup with DAP + echo module."""
    dap = dap_slot_info

    slots = [
        # DAP subslots (no IO data)
        IOSlot(
            slot=0,
            subslot=0x0001,
            module_ident=dap[1][0],
            submodule_ident=dap[1][1],
            input_length=0,
            output_length=0,
        ),
        IOSlot(
            slot=0,
            subslot=0x8000,
            module_ident=dap[0x8000][0],
            submodule_ident=dap[0x8000][1],
            input_length=0,
            output_length=0,
        ),
        IOSlot(
            slot=0,
            subslot=0x8001,
            module_ident=dap[0x8001][0],
            submodule_ident=dap[0x8001][1],
            input_length=0,
            output_length=0,
        ),
        # Echo module: 8B input + 8B output
        IOSlot(
            slot=ECHO_SLOT,
            subslot=ECHO_SUBSLOT,
            module_ident=GSDML_MOD_ECHO,
            submodule_ident=GSDML_SUBMOD_ECHO,
            input_length=ECHO_INPUT_LEN,
            output_length=ECHO_OUTPUT_LEN,
        ),
    ]

    return IOCRSetup(
        slots=slots,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_hold_factor=DATA_HOLD_FACTOR,
    )


@pytest.fixture(scope="class")
def cyclic_connection(device_info, iocr_setup):
    """Connect with IOCARSingle + IOCR, return (rpc, result, iocr_setup).

    Class-scoped: p-net only supports one AR at a time, so all tests
    in a class share the same connection.
    """
    info, src_mac = device_info
    # Brief pause to let device release any previous AR
    time.sleep(1)
    rpc = RPCCon(info, timeout=10.0)
    result = rpc.connect(
        src_mac=src_mac,
        with_alarm_cr=True,
        iocr_setup=iocr_setup,
    )
    try:
        yield rpc, result, iocr_setup
    finally:
        rpc.close()
        time.sleep(1)  # Let device release AR


# ---------------------------------------------------------------------------
# TestCyclicConnect
# ---------------------------------------------------------------------------


class TestCyclicConnect:
    """Test IOCARSingle connection with IOCR."""

    def test_connect_with_iocr(self, cyclic_connection):
        """IOCARSingle connect succeeds, returns ConnectResult."""
        _rpc, result, _setup = cyclic_connection
        assert result is not None
        assert isinstance(result, ConnectResult)

    def test_connect_result_has_frame_ids(self, cyclic_connection):
        """Input and output frame IDs are valid RT_CLASS_1 IDs."""
        _rpc, result, _setup = cyclic_connection
        assert result.input_frame_id >= 0x8000
        assert result.input_frame_id <= 0xFBFF
        assert result.output_frame_id >= 0x8000
        assert result.output_frame_id <= 0xFBFF

    def test_connect_result_has_cyclic(self, cyclic_connection):
        """ConnectResult.has_cyclic is True."""
        _rpc, result, _setup = cyclic_connection
        assert result.has_cyclic is True

    def test_alarm_cr_established(self, cyclic_connection):
        """AlarmCR reference is valid."""
        _rpc, result, _setup = cyclic_connection
        assert result.device_alarm_ref >= 0


# ---------------------------------------------------------------------------
# TestCyclicLifecycle
# ---------------------------------------------------------------------------


class TestCyclicLifecycle:
    """Test full cyclic IO lifecycle."""

    @pytest.fixture(autouse=True)
    def _lifecycle(self, device_info, iocr_setup, interface):
        """Run the full cyclic lifecycle for all tests in this class.

        Steps:
        1. Connect with IOCARSingle + IOCR
        2. PrmEnd
        3. ApplicationReady
        4. Start CyclicController, run for RUN_DURATION
        5. Stop
        6. Disconnect
        """
        info, src_mac = device_info

        # 1. Connect
        rpc = RPCCon(info, timeout=10.0)
        result = rpc.connect(
            src_mac=src_mac,
            with_alarm_cr=True,
            iocr_setup=iocr_setup,
        )
        assert result is not None and result.has_cyclic

        self.rpc = rpc
        self.result = result
        self.iocr_setup = iocr_setup

        # 2. PrmEnd
        rpc.prm_end()
        self.prm_end_ok = True

        # 3. ApplicationReady
        rpc.application_ready(timeout=30.0)
        self.app_ready_ok = True

        # 4. Build IOCRConfigs and start CyclicController
        dst_mac = bytes.fromhex(info.mac.replace(":", ""))

        input_iocr, output_iocr, out_iocs = build_iocr_configs(
            iocr_setup.slots,
            result.input_frame_id,
            result.output_frame_id,
        )

        cyclic = CyclicController(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            input_iocr=input_iocr,
            output_iocr=output_iocr,
        )

        # Set IOCS to GOOD (0x80) for DAP subslots in output frame.
        # These are consumer status bytes for the input data of submodules
        # that don't carry output data. Device requires them to be GOOD.
        for _slot, _subslot, offset in out_iocs:
            cyclic._output_builder._buffer[offset] = 0x80

        # Set initial echo output data
        cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, bytes(ECHO_OUTPUT_LEN))

        # Track received data
        self.received_data = []

        def on_input(slot, subslot, data):
            self.received_data.append((slot, subslot, bytes(data)))

        cyclic.on_input(on_input)

        cyclic.start()
        self.cyclic = cyclic

        # 5. Run - write echo pattern after brief startup
        time.sleep(0.5)
        echo_pattern = bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18])
        cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, echo_pattern)
        self.echo_pattern = echo_pattern

        time.sleep(RUN_DURATION)

        # 6. Stop
        cyclic.stop()
        self.stats = cyclic.stats

        yield

        # Cleanup
        try:
            rpc.close()
        except Exception:
            pass

    def test_prm_end_succeeds(self):
        """PrmEnd returns without error."""
        assert self.prm_end_ok

    def test_application_ready(self):
        """Device sends ApplicationReady CControl, controller confirms."""
        assert self.app_ready_ok

    def test_cyclic_frames_sent(self):
        """CyclicController sends output frames (frames_sent > 0)."""
        assert self.stats.frames_sent > 0

    def test_cyclic_frames_received(self):
        """CyclicController receives input frames (frames_received > 0)."""
        assert self.stats.frames_received > 0

    def test_echo_module_data(self):
        """Write data to echo output, read it back on input."""
        # Filter received data for echo module
        echo_data = [d for s, ss, d in self.received_data if s == ECHO_SLOT and ss == ECHO_SUBSLOT]
        assert len(echo_data) > 0, "No echo input data received"
        # The echo module should reflect our output pattern back
        assert any(d == self.echo_pattern for d in echo_data), (
            f"Echo pattern {self.echo_pattern.hex()} not found in "
            f"received data (got {len(echo_data)} frames, "
            f"last: {echo_data[-1].hex() if echo_data else 'none'})"
        )

    def test_disconnect_after_cyclic(self):
        """Clean disconnect works after cyclic exchange."""
        # disconnect() is idempotent - safe to call even if fixture cleanup also calls close()
        self.rpc.disconnect()
