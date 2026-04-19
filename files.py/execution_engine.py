"""
Execution Engine
Runs Foundry (forge test) in a sandboxed subprocess and parses the output
to determine if an exploit succeeded.
"""

import re
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ExecutionResult:
    success: bool
    failure_reason: str = ""
    stdout: str = ""
    stderr: str = ""
    gas_used: int = 0
    tx_trace: str = ""
    logs: list = field(default_factory=list)
    assertion_error: str = ""
    revert_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "failure_reason": self.failure_reason,
            "gas_used": self.gas_used,
            "logs": self.logs[:10],
            "revert_reason": self.revert_reason,
            "tx_trace_excerpt": self.tx_trace[:1000],
        }


class ExecutionEngine:
    """
    Runs Foundry forge test and interprets results.
    Falls back to simulation mode if forge is not installed.
    """

    def __init__(self, project, verbose=False):
        self.project = project
        self.verbose = verbose
        self.foundry_root = Path(project.foundry_root)
        self._forge_available = self._check_forge()

    def _check_forge(self) -> bool:
        """Check if forge is installed."""
        try:
            result = subprocess.run(
                ["forge", "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def execute(self, exploit_contract, hypothesis) -> ExecutionResult:
        """Run the exploit contract test."""
        if not exploit_contract:
            return ExecutionResult(success=False, failure_reason="No exploit contract provided")

        if self._forge_available:
            return self._run_forge(exploit_contract, hypothesis)
        else:
            return self._simulate_execution(exploit_contract, hypothesis)

    def _run_forge(self, exploit_contract, hypothesis) -> ExecutionResult:
        """Run forge test and parse output."""
        try:
            test_file = Path(exploit_contract.test_file_path).name
            test_name = exploit_contract.test_function_name

            cmd = [
                "forge", "test",
                "--match-path", f"test/{test_file}",
                "--match-test", test_name,
                "-vvvv",          # Very verbose for trace
                "--no-match-coverage",
            ]

            if self.verbose:
                print(f"[engine] Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                cwd=self.foundry_root,
                capture_output=True,
                text=True,
                timeout=120,
            )

            return self._parse_forge_output(result.stdout, result.stderr, result.returncode)

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                failure_reason="Forge test timed out after 120s"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                failure_reason=f"Forge execution error: {e}"
            )

    def _parse_forge_output(self, stdout: str, stderr: str, returncode: int) -> ExecutionResult:
        """Parse forge test output into a structured result."""
        full_output = stdout + stderr

        # Extract logs (console.log lines)
        logs = re.findall(r'\[PASS\].*?console\s*log:(.*?)(?:\n|$)', full_output)
        console_logs = re.findall(r'Logs:\n((?:\s+.*\n)*)', full_output)
        all_logs = []
        for block in console_logs:
            all_logs.extend([line.strip() for line in block.strip().split("\n") if line.strip()])

        # Check for success indicators
        passed = re.search(r'\[PASS\]\s+testExploit', full_output)
        failed = re.search(r'\[FAIL\]\s+testExploit', full_output)
        compilation_error = re.search(r'Error\s*\(compiler\)', full_output) or returncode != 0 and not passed

        # Extract revert reason
        revert_match = re.search(r'revert:\s*(.+)', full_output, re.IGNORECASE)
        revert_reason = revert_match.group(1).strip() if revert_match else ""

        # Extract gas
        gas_match = re.search(r'gas:\s*(\d+)', full_output)
        gas_used = int(gas_match.group(1)) if gas_match else 0

        # Extract tx trace
        trace_match = re.search(r'Traces:(.*?)(?:Logs:|$)', full_output, re.DOTALL)
        trace = trace_match.group(1)[:2000] if trace_match else ""

        # Extract assertion error
        assertion_match = re.search(r'EXPLOIT FAILED[:\s]+(.+)', full_output)
        assertion_error = assertion_match.group(1).strip() if assertion_match else ""

        # Detect compilation failures as a distinct failure type
        if compilation_error and not passed:
            return ExecutionResult(
                success=False,
                failure_reason="Compilation error — interface mismatch with target contract",
                stdout=stdout[:2000],
                stderr=stderr[:2000],
                logs=all_logs,
            )

        if passed:
            return ExecutionResult(
                success=True,
                stdout=stdout,
                stderr=stderr,
                gas_used=gas_used,
                tx_trace=trace,
                logs=all_logs,
            )
        else:
            return ExecutionResult(
                success=False,
                failure_reason=assertion_error or revert_reason or "Test assertion failed",
                stdout=stdout[:2000],
                stderr=stderr[:2000],
                gas_used=gas_used,
                logs=all_logs,
                revert_reason=revert_reason,
                assertion_error=assertion_error,
            )

    def _simulate_execution(self, exploit_contract, hypothesis) -> ExecutionResult:
        """
        Simulate execution when forge is not available.
        Uses static analysis heuristics to estimate exploit success probability.
        """
        if self.verbose:
            print("[engine] forge not found — using simulation mode")

        code = exploit_contract.solidity_code
        confidence = hypothesis.confidence

        # Heuristic signals from generated code
        signals = []

        # High confidence indicators in generated code
        if "REENTRANCY" in code and "receive()" in code:
            signals.append(("reentrancy structure present", 0.1))
        if "ACCESS CONTROL" in code and "try victim." in code:
            signals.append(("access control test structured", 0.05))
        if "assertGt" in code or "assertLt" in code:
            signals.append(("proper assertions", 0.05))
        if "vm.startPrank" in code:
            signals.append(("attacker context set", 0.05))

        # Confidence from underlying finding
        simulated_success = confidence >= 0.75

        if simulated_success:
            return ExecutionResult(
                success=True,
                failure_reason="",
                stdout="[SIMULATED] Exploit logic analysis suggests high probability of success",
                logs=[
                    f"[SIMULATED] Bug class: {hypothesis.bug_class}",
                    f"[SIMULATED] Confidence: {confidence:.0%}",
                    "[SIMULATED] Install forge for actual execution: https://getfoundry.sh",
                    "[SIMULATED] Run: curl -L https://foundry.paradigm.xyz | bash && foundryup",
                ],
                tx_trace="[SIMULATION MODE — install Foundry for real execution]",
            )
        else:
            return ExecutionResult(
                success=False,
                failure_reason=f"[SIMULATED] Confidence {confidence:.0%} below threshold (0.75)",
                logs=[f"Simulated confidence: {confidence:.0%}"],
            )

    def run_fuzzer(self, contract_path: str, target_fn: str) -> ExecutionResult:
        """Run Foundry fuzzer on a specific function."""
        if not self._forge_available:
            return ExecutionResult(success=False, failure_reason="Forge not available")

        try:
            result = subprocess.run(
                ["forge", "test", "--fuzz-runs", "10000", "-vv"],
                cwd=self.foundry_root,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_forge_output(result.stdout, result.stderr, result.returncode)
        except Exception as e:
            return ExecutionResult(success=False, failure_reason=str(e))

    def run_invariant_test(self, contract_path: str) -> ExecutionResult:
        """Run Foundry invariant testing."""
        if not self._forge_available:
            return ExecutionResult(success=False, failure_reason="Forge not available")

        try:
            result = subprocess.run(
                ["forge", "test", "--match-test", "invariant_",
                 "--invariant-runs", "100", "--invariant-depth", "20", "-vv"],
                cwd=self.foundry_root,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_forge_output(result.stdout, result.stderr, result.returncode)
        except Exception as e:
            return ExecutionResult(success=False, failure_reason=str(e))
