"""
Oracle / Price Manipulation Detector
Identifies contracts using spot prices from AMMs without TWAP protection —
the root cause of flash loan price manipulation attacks.

Real-world examples:
- Harvest Finance ($34M) — Curve spot price manipulation
- Cheese Bank ($3.3M) — Uniswap spot price
- bZx ($8M) — Kyber/Uniswap spot price in single tx
- Mango Markets ($116M) — self-manipulation of MNGO price
"""

import re
from .base import VulnerabilityDetector, Finding


class OracleManipulationDetector(VulnerabilityDetector):
    BUG_CLASS = "oracle_manipulation"
    SEVERITY = "CRITICAL"

    # Spot price sources (manipulable in same block/tx)
    SPOT_PRICE_PATTERNS = [
        (r'getReserves\s*\(\s*\)', "Uniswap V2 getReserves (spot)"),
        (r'slot0\s*\(\s*\)', "Uniswap V3 slot0 (spot price — manipulable)"),
        (r'observe\s*\(\s*\[0\]', "Uniswap V3 observe[0] (current tick)"),
        (r'getAmountsOut\s*\(', "UniswapRouter getAmountsOut (spot)"),
        (r'getAmountsIn\s*\(', "UniswapRouter getAmountsIn (spot)"),
        (r'get_dy\s*\(', "Curve get_dy (spot)"),
        (r'get_virtual_price\s*\(', "Curve get_virtual_price"),
        (r'getPricePerFullShare\s*\(', "Yearn getPricePerFullShare"),
        (r'latestAnswer\s*\(\s*\)', "Chainlink latestAnswer (deprecated, no staleness check)"),
        (r'latestRoundData\s*\(\s*\)', "Chainlink latestRoundData"),
        (r'\.price\s*\(\s*\)', "custom price() call"),
        (r'priceOf\s*\(', "custom priceOf() call"),
        (r'getPrice\s*\(', "custom getPrice()"),
        (r'oracle\.\w+\s*\(', "oracle call"),
        (r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)', "self balanceOf (manipulable reserve)"),
    ]

    # TWAP / safe oracle patterns (negative signals)
    TWAP_PATTERNS = [
        r'twap',
        r'TWAP',
        r'timeWeightedAverage',
        r'observations\[',
        r'consult\s*\(',
        r'\.observe\s*\(',
        r'periodSize',
        r'windowSize',
        r'granularity',
        r'AggregatorV3Interface',
        r'roundId',
    ]

    # Chainlink staleness check
    STALENESS_PATTERNS = [
        r'updatedAt',
        r'answeredInRound',
        r'block\.timestamp\s*-\s*updatedAt',
        r'require.*stale',
        r'MAX_DELAY',
    ]

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            # Global TWAP signal
            has_twap = any(re.search(p, source, re.IGNORECASE) for p in self.TWAP_PATTERNS)

            for fn_name, fn_body, start_line in self._iter_functions(source):
                findings.extend(
                    self._check_function(fn_name, fn_body, start_line,
                                        contract_name, has_twap)
                )

        self._log(f"Found {len(findings)} oracle manipulation finding(s)")
        return findings

    def _check_function(self, fn_name, fn_body, start_line,
                        contract_name, has_twap) -> list:
        findings = []

        for pattern, label in self.SPOT_PRICE_PATTERNS:
            if not re.search(pattern, fn_body):
                continue

            # Skip if TWAP-protected
            fn_has_twap = any(re.search(p, fn_body, re.IGNORECASE) for p in self.TWAP_PATTERNS)
            if has_twap and fn_has_twap:
                continue

            # Special: Chainlink with staleness check is OK
            if "Chainlink" in label or "latestRoundData" in label:
                has_staleness = any(re.search(p, fn_body) for p in self.STALENESS_PATTERNS)
                if has_staleness:
                    continue
                else:
                    findings.append(self._make_finding(
                        fn_name, fn_body, start_line, contract_name,
                        label,
                        "Chainlink oracle missing staleness check — stale price can be used "
                        "during network downtime or sequencer outage",
                        severity="HIGH",
                        confidence=0.85,
                        exploit_vector=(
                            "Wait for Chainlink update delay, use stale price to borrow "
                            "against overvalued collateral, drain protocol"
                        )
                    ))
                    continue

            confidence = self._score_confidence(fn_name, fn_body, label, has_twap)
            if confidence < 0.35:
                continue

            findings.append(self._make_finding(
                fn_name, fn_body, start_line, contract_name,
                label,
                (f"`{fn_name}` reads {label} — manipulable in same block via flash loan. "
                 f"Attacker can inflate/deflate price to drain collateral or arbitrage."),
                severity="CRITICAL",
                confidence=confidence,
                exploit_vector=(
                    f"1) Flash loan large amount  "
                    f"2) Manipulate {label}  "
                    f"3) Call {fn_name}() with distorted price  "
                    f"4) Repay flash loan + keep profit"
                )
            ))

        return findings

    def _make_finding(self, fn_name, fn_body, start_line, contract_name,
                      label, description, severity, confidence, exploit_vector) -> Finding:
        return Finding(
            bug_class=self.BUG_CLASS,
            severity=severity,
            description=description,
            function_name=fn_name,
            contract_name=contract_name,
            line_numbers=[start_line],
            confidence=confidence,
            attack_surface=f"price oracle: {label}",
            exploit_vector=exploit_vector,
            raw_evidence=fn_body[:400],
            exploit_hints={
                "vulnerable_function": fn_name,
                "oracle_type": label,
                "needs_flash_loan": True,
                "needs_large_capital": True,
            }
        )

    def _score_confidence(self, fn_name, fn_body, label, has_global_twap) -> float:
        confidence = 0.65

        if any(k in fn_name.lower() for k in ["borrow", "collateral", "liquidat", "price", "value"]):
            confidence += 0.15
        if "flashLoan" in fn_body or "flash" in fn_body.lower():
            confidence -= 0.20  # might already account for it
        if has_global_twap:
            confidence -= 0.30
        if "getReserves" in label or "slot0" in label:
            confidence += 0.10  # most dangerous patterns

        return max(0.0, min(1.0, confidence))
