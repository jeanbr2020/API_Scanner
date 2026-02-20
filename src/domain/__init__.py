"""Domain layer - Regras de negócio puras."""

from .enums import Severity, ScanStatus
from .exceptions import (
    DomainException,
    InvalidTargetError,
    PrivateIPNotAllowedError,
    InvalidScanStateError,
    InvalidSeverityError
)
from .entities import Target, Vulnerability, Scan
from .value_objects import ScanResult

__all__ = [
    "Severity",
    "ScanStatus",
    "DomainException",
    "InvalidTargetError",
    "PrivateIPNotAllowedError",
    "InvalidScanStateError",
    "InvalidSeverityError",
    "Target",
    "Vulnerability",
    "Scan",
    "ScanResult",
]