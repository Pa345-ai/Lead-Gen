"""
Vulnerability Analyzer
Orchestrates all detectors over the normalized project sources.
Deduplicates, ranks, and returns prioritized findings.
"""

from src.detectors import ALL_DETECTORS, Finding


class VulnerabilityAnalyzer:
    """
    Runs all registered detectors and returns a ranked, deduplicated
    list of Finding objects.
    """

    SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self, project, target_bugs=None, verbose=False):
        self.project = project
        self.target_bugs = target_bugs  # None = all
        self.verbose = verbose
        self.sources = project.raw_sources
        self.compiler_version = project.compiler_version

    def analyze(self) -> list:
        """Run all detectors, return sorted, deduplicated findings."""
        all_findings = []

        detectors_to_run = (
            {k: v for k, v in ALL_DETECTORS.items() if k in self.target_bugs}
            if self.target_bugs else ALL_DETECTORS
        )

        for name, DetectorClass in detectors_to_run.items():
            try:
                detector = DetectorClass(
                    sources=self.sources,
                    compiler_version=self.compiler_version,
                    verbose=self.verbose
                )
                findings = detector.detect()
                all_findings.extend(findings)

                if self.verbose:
                    print(f"[analyzer] {name}: {len(findings)} finding(s)")

            except Exception as e:
                if self.verbose:
                    print(f"[analyzer] {name} ERROR: {e}")

        # Deduplicate
        unique = self._deduplicate(all_findings)

        # Sort by severity then confidence
        unique.sort(key=lambda f: (
            self.SEVERITY_RANK.get(f.severity, 99),
            -f.confidence
        ))

        if self.verbose:
            print(f"[analyzer] Total: {len(unique)} unique finding(s) "
                  f"({len(all_findings) - len(unique)} duplicates removed)")

        return unique

    def _deduplicate(self, findings: list) -> list:
        """Remove findings with identical (bug_class, function_name, contract_name)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.bug_class, f.function_name, f.contract_name)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
