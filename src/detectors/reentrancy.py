"""
Reentrancy Detector
Detects CEI (Check-Effects-Interactions) violations where external calls
precede state updates — the classic reentrancy pattern that has drained
hundreds of millions from DeFi protocols.

Known real-world examples: The DAO ($60M), Cream Finance ($18M), Fei/Rari ($80M)
"""

import re
from .base import VulnerabilityDetector, Finding


class ReentrancyDetector(VulnerabilityDetector):
    BUG_CLASS = "reentrancy"
    SEVERITY = "CRITICAL"

    # External call patterns
    EXTERNAL_CALL_PATTERNS = [
        (r'\.call\s*\{', "low-level .call{}"),
        (r'\.call\s*\(', "low-level .call()"),
        (r'\.transfer\s*\(', ".transfer()"),
        (r'\.send\s*\(', ".send()"),
        (r'\btransfer\b.*\(', "token transfer"),
        (r'IUniswap\w*\s*\(', "Uniswap call"),
        (r'IERC20\w*\s*\([^)]+\)\.(transfer|transferFrom)', "ERC20 transfer"),
        (r'\.swap\s*\(', "swap call"),
        (r'\.safeTransfer\b', "safeTransfer"),
        (r'\.safeTransferFrom\b', "safeTransferFrom"),
    ]

    # State mutation patterns
    STATE_MUTATION_PATTERNS = [
        r'balances\s*\[',
        r'balance\s*[+-]=',
        r'\w+\s*\[msg\.sender\]\s*[+-=]',
        r'\w+\s*\[_\w+\]\s*=',
        r'totalSupply\s*[+-]=',
        r'userInfo\s*\[',
        r'deposits\s*\[',
        r'shares\s*\[',
        r'_burn\s*\(',
        r'_mint\s*\(',
    ]

    # Protective patterns
    GUARD_PATTERNS = [
        r'nonReentrant',
        r'ReentrancyGuard',
        r'_status\s*==\s*_ENTERED',
        r'locked\s*=\s*true',
        r'mutex',
    ]

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            # Skip if contract has a blanket reentrancy guard
            has_global_guard = any(
                re.search(p, source) for p in self.GUARD_PATTERNS
            )

            for fn_name, fn_body, start_line in self._iter_functions(source):
                f = self._check_function(
                    fn_name, fn_body, start_line,
                    contract_name, filename, has_global_guard
                )
                if f:
                    findings.append(f)

        self._log(f"Found {len(findings)} reentrancy finding(s)")
        return findings

    def _check_function(self, fn_name, fn_body, start_line,
                        contract_name, filename, has_global_guard) -> Finding | None:
        """
        Detect reentrancy in a single function.
        Strategy: find first external call position vs first state mutation position.
        If call < mutation → CEI violation.
        """
        # Check for function-level guard
        if any(re.search(p, fn_body) for p in self.GUARD_PATTERNS):
            return None

        # Find positions of external calls
        call_positions = []
        call_types = []
        for pattern, label in self.EXTERNAL_CALL_PATTERNS:
            for m in re.finditer(pattern, fn_body):
                call_positions.append(m.start())
                call_types.append(label)

        if not call_positions:
            return None

        first_call_pos = min(call_positions)
        first_call_type = call_types[call_positions.index(first_call_pos)]

        # Find positions of state mutations
        mutation_positions = []
        for pattern in self.STATE_MUTATION_PATTERNS:
            for m in re.finditer(pattern, fn_body):
                mutation_positions.append(m.start())

        if not mutation_positions:
            return None

        # Find state mutations AFTER the external call (CEI violation)
        mutations_after_call = [p for p in mutation_positions if p > first_call_pos]

        if not mutations_after_call:
            return None

        # Calculate confidence
        confidence = self._calculate_confidence(
            fn_body, has_global_guard, fn_name, first_call_type
        )

        if confidence < 0.3:
            return None

        # Extract evidence snippet
        lines = fn_body.split("\n")
        call_line = fn_body[:first_call_pos].count("\n")
        evidence = "\n".join(lines[max(0, call_line-1):call_line+4])

        return Finding(
            bug_class=self.BUG_CLASS,
            severity=self.SEVERITY,
            description=(
                f"CEI violation in `{fn_name}`: {first_call_type} at pos {first_call_pos} "
                f"precedes {len(mutations_after_call)} state update(s). "
                f"Attacker can re-enter before balances are updated."
            ),
            function_name=fn_name,
            contract_name=contract_name,
            line_numbers=[start_line + fn_body[:first_call_pos].count("\n")],
            confidence=confidence,
            attack_surface="external call before state update",
            exploit_vector=f"Deploy attacker contract, call {fn_name}(), re-enter in receive()/fallback()",
            raw_evidence=evidence,
            exploit_hints={
                "vulnerable_function": fn_name,
                "call_type": first_call_type,
                "mutations_after_call": len(mutations_after_call),
                "has_receive": "receive()" in self.sources.get(filename, ""),
                "has_fallback": "fallback()" in self.sources.get(filename, ""),
                "likely_eth": "transfer" in first_call_type or ".call" in first_call_type,
            }
        )

    def _calculate_confidence(self, fn_body, has_global_guard,
                               fn_name, call_type) -> float:
        """Weighted confidence scoring."""
        confidence = 0.7

        # Rewards
        if "withdraw" in fn_name.lower():
            confidence += 0.15
        if "claim" in fn_name.lower() or "redeem" in fn_name.lower():
            confidence += 0.10
        if ".call" in call_type:
            confidence += 0.10  # raw call = more dangerous
        if "msg.value" in fn_body or "msg.sender" in fn_body:
            confidence += 0.05

        # Penalties
        if has_global_guard:
            confidence -= 0.50
        if "require(" in fn_body and "locked" in fn_body:
            confidence -= 0.30
        if "modifier" in fn_body:
            confidence -= 0.10

        return max(0.0, min(1.0, confidence))
