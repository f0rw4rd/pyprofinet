"""
PROFINET IO Record Data Index definitions.

Provides constants for all standardized PROFINET indices organized by category.
Index ranges determine addressing scope:
- 0x0000-0x7FFF: User/manufacturer specific
- 0x8000-0x8FFF: Subslot level
- 0xA000-0xAFFF: I&M data (slot level)
- 0xC000-0xCFFF: Slot level
- 0xE000-0xEFFF: AR (Application Relationship) level
- 0xF000-0xF7FF: API level
- 0xF800-0xFBFF: Device level
"""

from typing import Dict, List, Tuple

# =============================================================================
# I&M (Identification & Maintenance) Indices - 0xAFFx
# =============================================================================

IM0 = 0xAFF0  # Mandatory: VendorID, OrderID, SerialNumber, HW/SW revision
IM1 = 0xAFF1  # Tag_Function + Tag_Location
IM2 = 0xAFF2  # Installation_Date
IM3 = 0xAFF3  # Descriptor
IM4 = 0xAFF4  # Safety signature (PROFIsafe)
IM5 = 0xAFF5  # Communication stack info
IM0_FILTER_DATA = 0xF840  # Lists all submodules with I&M data

# =============================================================================
# Diagnosis Indices - Pattern: 0x__0A/B/C
# =============================================================================

# Subslot level (0x800x)
DIAG_CHANNEL_SUBSLOT = 0x800A
DIAG_ALL_SUBSLOT = 0x800B
DIAG_MAINTENANCE_SUBSLOT = 0x800C

# Slot level (0xC00x)
DIAG_CHANNEL_SLOT = 0xC00A
DIAG_ALL_SLOT = 0xC00B
DIAG_MAINTENANCE_SLOT = 0xC00C

# AR level (0xE00x)
DIAG_CHANNEL_AR = 0xE00A
DIAG_ALL_AR = 0xE00B
DIAG_MAINTENANCE_AR = 0xE00C

# API level (0xF00x)
DIAG_CHANNEL_API = 0xF00A
DIAG_ALL_API = 0xF00B
DIAG_MAINTENANCE_API = 0xF00C

# Device level
DIAG_DEVICE = 0xF80C  # All diagnosis for entire device

# =============================================================================
# Maintenance Indices - Pattern: 0x__10-13
# =============================================================================

MAINT_REQUIRED_CHANNEL_SUBSLOT = 0x8010
MAINT_DEMANDED_CHANNEL_SUBSLOT = 0x8011
MAINT_REQUIRED_ALL_SUBSLOT = 0x8012
MAINT_DEMANDED_ALL_SUBSLOT = 0x8013

# =============================================================================
# Configuration/Identification Indices
# =============================================================================

# Subslot level
EXPECTED_ID_SUBSLOT = 0x8000
REAL_ID_SUBSLOT = 0x8001

# AR level
EXPECTED_ID_AR = 0xE000
REAL_ID_AR = 0xE001
MODULE_DIFF_BLOCK = 0xE002  # Deviation between expected and real

# API level
REAL_ID_API = 0xF000

# Device level
AR_DATA = 0xF820
API_DATA = 0xF821
PDEV_DATA = 0xF831
PD_REAL_DATA = 0xF841
PD_EXPECTED_DATA = 0xF842
AUTO_CONFIG = 0xF850
LOG_DATA = 0xF830

# =============================================================================
# PDPort Indices (for port subslots 0x8001, 0x8002, etc.)
# =============================================================================

PD_PORT_DATA_REAL = 0x802A
PD_PORT_DATA_CHECK = 0x802B
PD_IR_DATA = 0x802C
PD_SYNC_DATA = 0x802D
PD_PORT_DATA_ADJUST = 0x802F
PD_PORT_STATISTIC = 0x8072

# =============================================================================
# PDInterface Indices (for interface subslot 0x8000)
# =============================================================================

PD_NC_DATA_CHECK = 0x8070
PD_INTERFACE_ADJUST = 0x8071
PD_INTERFACE_DATA_REAL = 0x8080
PD_INTERFACE_FSU_ADJUST = 0x8090

# =============================================================================
# Fiber Optic Indices
# =============================================================================

PD_PORT_FO_DATA_REAL = 0x8060
PD_PORT_FO_DATA_CHECK = 0x8061
PD_PORT_FO_DATA_ADJUST = 0x8062
PD_PORT_SFP_DATA_CHECK = 0x8063

# =============================================================================
# MRP (Media Redundancy Protocol) Indices
# =============================================================================

# Interface level (subslot 0x8000)
PD_INTERFACE_MRP_DATA_REAL = 0x8050
PD_INTERFACE_MRP_DATA_CHECK = 0x8051
PD_INTERFACE_MRP_DATA_ADJUST = 0x8052

# Port level
PD_PORT_MRP_DATA_ADJUST = 0x8053
PD_PORT_MRP_DATA_REAL = 0x8054
PD_PORT_MRP_IC_DATA_ADJUST = 0x8055
PD_PORT_MRP_IC_DATA_CHECK = 0x8056
PD_PORT_MRP_IC_DATA_REAL = 0x8057

# =============================================================================
# Sync/PTCP Indices
# =============================================================================

PD_IR_SUBFRAME_DATA = 0x8020
ISOCHRONOUS_MODE_DATA = 0x8030
PD_TIME_DATA = 0x8031

# =============================================================================
# I/O Data Indices
# =============================================================================

SUBSTITUTE_VALUES = 0x801E
RECORD_INPUT_DATA = 0x8028
RECORD_OUTPUT_DATA = 0x8029

# =============================================================================
# Asset Management Indices
# =============================================================================

AM_DEVICE_ID = 0xF8E0
AM_FULL_INFO = 0xF8E1
AM_HW_ONLY = 0xF8E2
AM_FW_ONLY = 0xF8E3
AM_LOCATION_SLOT = 0xFBE0
AM_LOCATION_TREE = 0xFBE1
AM_DATA = 0xFBF0

# =============================================================================
# PROFIsafe Indices
# =============================================================================

F_PARAMETER_BLOCK = 0x0100
F_PRM_FLAG1 = 0x0101
F_PRM_FLAG2 = 0x0102
F_PARAMETER_WRITE = 0xE000
F_PARAMETER_READ = 0xE001

# =============================================================================
# PROFIenergy Index
# =============================================================================

PROFIENERGY = 0x80A0

# =============================================================================
# AR-specific Indices
# =============================================================================

WRITE_MULTIPLE = 0xE040
AR_FSU_DATA_ADJUST = 0xE050

# =============================================================================
# Standard DAP Subslots
# =============================================================================

SUBSLOT_DAP = 0x0001
SUBSLOT_INTERFACE = 0x8000
SUBSLOT_PORT1 = 0x8001
SUBSLOT_PORT2 = 0x8002


# =============================================================================
# Index Categories for Enumeration
# =============================================================================

# Critical indices that should always be tested
CRITICAL_INDICES: List[Tuple[int, str]] = [
    (IM0, "I&M0 (mandatory)"),
    (IM0_FILTER_DATA, "I&M0FilterData"),
    (DIAG_DEVICE, "Device Diagnosis"),
    (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
    (PD_REAL_DATA, "PDRealData"),
    (AR_DATA, "ARData"),
    (LOG_DATA, "LogData"),
]

# I&M indices
IM_INDICES: List[Tuple[int, str]] = [
    (IM0, "I&M0"),
    (IM1, "I&M1"),
    (IM2, "I&M2"),
    (IM3, "I&M3"),
    (IM4, "I&M4"),
    (IM5, "I&M5"),
]

# Diagnosis indices by scope
DIAGNOSIS_INDICES: Dict[str, List[Tuple[int, str]]] = {
    "subslot": [
        (DIAG_CHANNEL_SUBSLOT, "DiagnosisChannel"),
        (DIAG_ALL_SUBSLOT, "DiagnosisAll"),
        (DIAG_MAINTENANCE_SUBSLOT, "DiagnosisMaintenance"),
    ],
    "slot": [
        (DIAG_CHANNEL_SLOT, "DiagnosisChannel"),
        (DIAG_ALL_SLOT, "DiagnosisAll"),
        (DIAG_MAINTENANCE_SLOT, "DiagnosisMaintenance"),
    ],
    "ar": [
        (DIAG_CHANNEL_AR, "DiagnosisChannel"),
        (DIAG_ALL_AR, "DiagnosisAll"),
        (DIAG_MAINTENANCE_AR, "DiagnosisMaintenance"),
    ],
    "api": [
        (DIAG_CHANNEL_API, "DiagnosisChannel"),
        (DIAG_ALL_API, "DiagnosisAll"),
        (DIAG_MAINTENANCE_API, "DiagnosisMaintenance"),
    ],
    "device": [
        (DIAG_DEVICE, "DeviceDiagnosis"),
    ],
}

# Port-related indices
PORT_INDICES: List[Tuple[int, str]] = [
    (PD_PORT_DATA_REAL, "PDPortDataReal"),
    (PD_PORT_DATA_CHECK, "PDPortDataCheck"),
    (PD_PORT_DATA_ADJUST, "PDPortDataAdjust"),
    (PD_PORT_STATISTIC, "PDPortStatistic"),
    (PD_PORT_MRP_DATA_REAL, "PDPortMrpDataReal"),
]

# Interface-related indices
INTERFACE_INDICES: List[Tuple[int, str]] = [
    (PD_INTERFACE_DATA_REAL, "PDInterfaceDataReal"),
    (PD_INTERFACE_MRP_DATA_REAL, "PDInterfaceMrpDataReal"),
    (PD_NC_DATA_CHECK, "PDNCDataCheck"),
]

# Device-level indices
DEVICE_INDICES: List[Tuple[int, str]] = [
    (AR_DATA, "ARData"),
    (API_DATA, "APIData"),
    (PDEV_DATA, "PDevData"),
    (PD_REAL_DATA, "PDRealData"),
    (PD_EXPECTED_DATA, "PDExpectedData"),
    (LOG_DATA, "LogData"),
    (AUTO_CONFIG, "AutoConfiguration"),
]

# All standard indices for comprehensive enumeration
ALL_STANDARD_INDICES: List[Tuple[int, str]] = (
    IM_INDICES +
    DIAGNOSIS_INDICES["subslot"] +
    DIAGNOSIS_INDICES["device"] +
    PORT_INDICES +
    INTERFACE_INDICES +
    DEVICE_INDICES +
    [
        (EXPECTED_ID_SUBSLOT, "ExpectedIdentificationData"),
        (REAL_ID_SUBSLOT, "RealIdentificationData"),
        (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
        (SUBSTITUTE_VALUES, "SubstituteValues"),
        (RECORD_INPUT_DATA, "RecordInputData"),
        (RECORD_OUTPUT_DATA, "RecordOutputData"),
    ]
)


def get_index_name(index: int) -> str:
    """Get human-readable name for an index."""
    for idx, name in ALL_STANDARD_INDICES:
        if idx == index:
            return name

    # Check range for category
    if 0x0000 <= index <= 0x7FFF:
        return f"User-specific (0x{index:04X})"
    elif 0xAFF0 <= index <= 0xAFFF:
        return f"I&M{index - 0xAFF0}"
    elif 0x8000 <= index <= 0x8FFF:
        return f"Subslot data (0x{index:04X})"
    elif 0xC000 <= index <= 0xCFFF:
        return f"Slot data (0x{index:04X})"
    elif 0xE000 <= index <= 0xEFFF:
        return f"AR data (0x{index:04X})"
    elif 0xF000 <= index <= 0xF7FF:
        return f"API data (0x{index:04X})"
    elif 0xF800 <= index <= 0xFBFF:
        return f"Device data (0x{index:04X})"
    else:
        return f"Unknown (0x{index:04X})"


def get_scope(index: int) -> str:
    """Get the addressing scope for an index."""
    if 0x0000 <= index <= 0x7FFF:
        return "user"
    elif 0x8000 <= index <= 0x8FFF:
        return "subslot"
    elif 0xA000 <= index <= 0xAFFF:
        return "slot"
    elif 0xC000 <= index <= 0xCFFF:
        return "slot"
    elif 0xE000 <= index <= 0xEFFF:
        return "ar"
    elif 0xF000 <= index <= 0xF7FF:
        return "api"
    elif 0xF800 <= index <= 0xFBFF:
        return "device"
    else:
        return "unknown"
