"""
Base detector interface.
All vulnerability detectors inherit from VulnerabilityDetector.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Optional
import enum


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability finding from a detector."""
    bug_class: str
    severity: str                  # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    function_name: Optional[str] = None
    contract_name: Optional[str] = None
    line_numbers: list = field(default_factory=list)
    confidence: float = 0.7        # 0.0 – 1.0
    attack_surface: str = ""       # e.g. "external call", "state update"
    exploit_vector: str = ""       # short attack description
    raw_evidence: str = ""         # the actual code snippet
    exploit_hints: dict = field(default_factory=dict)  # extra context for generators

    def to_dict(self) -> dict:
        return asdict(self)


class VulnerabilityDetector(ABC):
    """
    Abstract base for all vulnerability detectors.

    Each detector:
    1. Receives raw source text + parsed metadata
    2. Returns a list of Finding objects
    3. Runs quickly (regex + lightweight AST) — not a full compiler
    """

    BUG_CLASS: str = "unknown"
    SEVERITY: str = "MEDIUM"

    def __init__(self, sources: dict, compiler_version: str, verbose: bool = False):
        self.sources = sources        # {filename: source_text}
        self.compiler_version = compiler_version
        self.verbose = verbose

    @abstractmethod
    def detect(self) -> list:
        """Run detection. Return list of Finding objects."""
        pass

    # ── Shared helpers ────────────────────────────────────────────────

    def _iter_functions(self, source: str):
        """
        Yield (function_name, function_body, start_line) tuples.
        Simple regex-based splitter — not a full parser.
        """
        import re
        fn_pattern = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
            re.MULTILINE
        )
        lines = source.split("\n")
        line_offsets = [0]
        for line in lines:
            line_offsets.append(line_offsets[-1] + len(line) + 1)

        matches = list(fn_pattern.finditer(source))
        for i, m in enumerate(matches):
            fn_name = m.group(1)
            start = m.start()
            end = matches[i+1].start() if i+1 < len(matches) else len(source)
            body = source[start:end]
            start_line = source[:start].count("\n") + 1
            yield fn_name, body, start_line

    def _contract_name(self, source: str) -> str:
        """Extract the primary contract name."""
        import re
        m = re.search(r'contract\s+(\w+)', source)
        return m.group(1) if m else "UnknownContract"

    def _is_pre_080(self) -> bool:
        """Return True if compiler < 0.8.0 (overflow unprotected)."""
        try:
            parts = self.compiler_version.split(".")
            return int(parts[1]) < 8
        except Exception:
            return False

    def _has_reentrancy_guard(self, source: str) -> bool:
        """Check for ReentrancyGuard or nonReentrant modifier."""
        import re
        return bool(re.search(r'nonReentrant|ReentrancyGuard', source))

    def _log(self, msg: str):
        if self.verbose:
            print(f"[{self.BUG_CLASS}] {msg}")
