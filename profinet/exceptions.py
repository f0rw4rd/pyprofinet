"""
PROFINET exception hierarchy.

Provides specific exception types for different error conditions.
"""

from __future__ import annotations


class ProfinetError(Exception):
    """Base exception for all PROFINET errors."""

    pass


class DCPError(ProfinetError):
    """DCP protocol errors."""

    pass


class DCPTimeoutError(DCPError):
    """DCP operation timed out."""

    pass


class DCPDeviceNotFoundError(DCPError):
    """Device not found via DCP."""

    pass


class RPCError(ProfinetError):
    """DCE/RPC protocol errors."""

    pass


class RPCTimeoutError(RPCError):
    """RPC operation timed out."""

    pass


class RPCFaultError(RPCError):
    """RPC returned fault response."""

    def __init__(self, message: str, fault_code: int = 0):
        super().__init__(message)
        self.fault_code = fault_code


class RPCConnectionError(RPCError):
    """Failed to establish RPC connection."""

    pass


class PNIOError(RPCError):
    """PNIO application error with error codes.

    Error code structure (4 bytes, big-endian):
        Byte 0: ErrorCode2 (specific error)
        Byte 1: ErrorCode1 (category)
        Byte 2: ErrorDecode (0x80 = PNIO)
        Byte 3: ErrorCode (0xDE = application error)
    """

    # ErrorCode values
    PNIO_ERROR = 0xDE

    # ErrorCode1 categories
    EC1_INVALID_INDEX = 0xB0
    EC1_WRITE_LENGTH = 0xB1
    EC1_RESOURCE = 0xB2          # Slot/Subslot errors
    EC1_ACCESS = 0xB3
    EC1_APPLICATION = 0xB4       # API errors
    EC1_USER_SPECIFIC_1 = 0xB5
    EC1_USER_SPECIFIC_2 = 0xB6
    EC1_USER_SPECIFIC_3 = 0xB7
    EC1_USER_SPECIFIC_4 = 0xB8
    EC1_USER_SPECIFIC_5 = 0xB9

    # ErrorCode2 for EC1_RESOURCE (0xB2)
    EC2_INVALID_SLOT = 0x07
    EC2_INVALID_SUBSLOT = 0x08

    # ErrorCode2 for EC1_APPLICATION (0xB4)
    EC2_INVALID_API = 0x06

    # Human-readable error messages
    ERROR_MESSAGES = {
        (EC1_INVALID_INDEX, 0x00): "Invalid index",
        (EC1_WRITE_LENGTH, 0x00): "Write length error",
        (EC1_RESOURCE, EC2_INVALID_SLOT): "Invalid slot number",
        (EC1_RESOURCE, EC2_INVALID_SUBSLOT): "Invalid subslot number",
        (EC1_ACCESS, 0x00): "Access denied",
        (EC1_APPLICATION, EC2_INVALID_API): "Invalid API number",
    }

    def __init__(
        self,
        message: str,
        error_code: int = 0,
        error_decode: int = 0,
        error_code1: int = 0,
        error_code2: int = 0,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.error_decode = error_decode
        self.error_code1 = error_code1
        self.error_code2 = error_code2

    @classmethod
    def from_args_status(cls, args_status: int) -> "PNIOError":
        """Create PNIOError from ArgsStatus field (4 bytes, big-endian)."""
        error_code2 = (args_status >> 24) & 0xFF
        error_code1 = (args_status >> 16) & 0xFF
        error_decode = (args_status >> 8) & 0xFF
        error_code = args_status & 0xFF

        # Get human-readable message
        key = (error_code1, error_code2)
        if key in cls.ERROR_MESSAGES:
            msg = cls.ERROR_MESSAGES[key]
        else:
            msg = f"PNIO error (EC1=0x{error_code1:02X}, EC2=0x{error_code2:02X})"

        return cls(
            message=msg,
            error_code=error_code,
            error_decode=error_decode,
            error_code1=error_code1,
            error_code2=error_code2,
        )

    def __str__(self) -> str:
        return (
            f"{self.args[0]} "
            f"[ErrorCode1=0x{self.error_code1:02X}, ErrorCode2=0x{self.error_code2:02X}]"
        )


class ValidationError(ProfinetError):
    """Input validation error."""

    pass


class InvalidMACError(ValidationError):
    """Invalid MAC address format."""

    pass


class InvalidIPError(ValidationError):
    """Invalid IP address format."""

    pass


class SocketError(ProfinetError):
    """Socket operation error."""

    pass


class PermissionDeniedError(SocketError):
    """Insufficient permissions for raw socket."""

    pass
