"""
Vulnerability Detector Registry
All 10 critical bug classes in one place.
"""

from .base import VulnerabilityDetector, Finding, Severity
from .reentrancy import ReentrancyDetector
from .access_control import AccessControlDetector
from .oracle_manipulation import OracleManipulationDetector
from .remaining_detectors import (
    IntegerOverflowDetector,
    FlashLoanDetector,
    UncheckedReturnDetector,
    FrontRunningDetector,
    DelegatecallDetector,
    StorageCollisionDetector,
    LogicFlawDetector,
)

ALL_DETECTORS = {
    "reentrancy":          ReentrancyDetector,
    "access_control":      AccessControlDetector,
    "oracle_manipulation": OracleManipulationDetector,
    "integer_overflow":    IntegerOverflowDetector,
    "flash_loan":          FlashLoanDetector,
    "unchecked_return":    UncheckedReturnDetector,
    "front_running":       FrontRunningDetector,
    "delegatecall":        DelegatecallDetector,
    "storage_collision":   StorageCollisionDetector,
    "logic_flaw":          LogicFlawDetector,
}

__all__ = [
    "VulnerabilityDetector", "Finding", "Severity",
    "ALL_DETECTORS",
    "ReentrancyDetector", "AccessControlDetector",
    "OracleManipulationDetector", "IntegerOverflowDetector",
    "FlashLoanDetector", "UncheckedReturnDetector",
    "FrontRunningDetector", "DelegatecallDetector",
    "StorageCollisionDetector", "LogicFlawDetector",
]
