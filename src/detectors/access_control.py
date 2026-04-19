"""
Access Control Bypass Detector
Finds missing or bypassable authorization on privileged operations.

Real-world examples:
- Poly Network ($611M) — unprotected cross-chain function
- Ronin Bridge ($625M) — compromised validator keys
- Wormhole ($320M) — missing guardian set verification
- MonoX ($31M) — token price manipulation via unprotected swap
"""

import re
from .base import VulnerabilityDetector, Finding


class AccessControlDetector(VulnerabilityDetector):
    BUG_CLASS = "access_control"
    SEVERITY = "CRITICAL"

    # Functions that SHOULD be protected
    SENSITIVE_FUNCTION_PATTERNS = [
        (r'\bmint\b', "token minting"),
        (r'\bburn\b', "token burning"),
        (r'\bwithdraw\b', "fund withdrawal"),
        (r'\bsetOwner\b|\btransferOwnership\b', "ownership transfer"),
        (r'\bupgradeTo\b|\bupgradeToAndCall\b', "proxy upgrade"),
        (r'\bsetImplementation\b', "implementation change"),
        (r'\binitialize\b|\binitializer\b', "initializer"),
        (r'\bsetPrice\b|\bupdatePrice\b', "price update"),
        (r'\bsetOracle\b|\bupdateOracle\b', "oracle update"),
        (r'\bsetFee\b|\bupdateFee\b', "fee update"),
        (r'\bpause\b|\bunpause\b', "pause control"),
        (r'\baddValidator\b|\bremoveValidator\b', "validator management"),
        (r'\bsetWhitelist\b|\baddWhitelist\b', "whitelist management"),
        (r'\bexecute\b|\bexecuteTransaction\b', "transaction execution"),
        (r'\bsetConfig\b|\bupdateConfig\b', "config update"),
        (r'\bemergencyWithdraw\b', "emergency withdrawal"),
    ]

    # Authorization check patterns
    AUTH_PATTERNS = [
        r'onlyOwner',
        r'onlyRole\s*\(',
        r'onlyAdmin',
        r'require\s*\(\s*msg\.sender\s*==',
        r'require\s*\(\s*_msgSender\(\)\s*==',
        r'require\s*\(\s*hasRole\s*\(',
        r'_checkRole\s*\(',
        r'AccessControl',
        r'Ownable',
        r'require\s*\(\s*isOwner\(',
        r'require\s*\(\s*isAdmin\(',
        r'msg\.sender\s*==\s*owner',
        r'msg\.sender\s*==\s*admin',
        r'require.*authorized',
        r'require.*whitelist',
        r'onlyGovernance',
        r'onlyMultisig',
    ]

    # Unprotected initializer detection
    INIT_PATTERNS = [
        r'function\s+initialize\s*\(',
        r'function\s+init\s*\(',
        r'function\s+__\w+_init\s*\(',
    ]

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            # Check 1: Unprotected sensitive functions
            findings.extend(
                self._check_unprotected_functions(source, contract_name)
            )

            # Check 2: Unprotected initializers (proxy pattern)
            findings.extend(
                self._check_unprotected_initializers(source, contract_name)
            )

            # Check 3: tx.origin used for auth (phishing vector)
            findings.extend(
                self._check_tx_origin(source, contract_name)
            )

            # Check 4: Overly permissive role assignment
            findings.extend(
                self._check_role_escalation(source, contract_name)
            )

        self._log(f"Found {len(findings)} access control finding(s)")
        return findings

    def _check_unprotected_functions(self, source, contract_name) -> list:
        findings = []

        for fn_name, fn_body, start_line in self._iter_functions(source):
            for pattern, label in self.SENSITIVE_FUNCTION_PATTERNS:
                if not re.search(pattern, fn_name, re.IGNORECASE):
                    continue

                # Check if protected
                has_auth = any(re.search(ap, fn_body) for ap in self.AUTH_PATTERNS)
                if has_auth:
                    continue

                # Check visibility — internal/private are OK
                visibility_match = re.search(
                    r'function\s+' + fn_name + r'\s*\([^)]*\)\s*(public|external|internal|private)',
                    source
                )
                if visibility_match:
                    vis = visibility_match.group(1)
                    if vis in ("internal", "private"):
                        continue

                confidence = self._score_confidence(fn_name, fn_body, label)
                if confidence < 0.4:
                    continue

                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity="CRITICAL" if confidence > 0.7 else "HIGH",
                    description=(
                        f"Unprotected {label} function `{fn_name}` — "
                        f"no authorization check detected. Any caller can invoke this."
                    ),
                    function_name=fn_name,
                    contract_name=contract_name,
                    line_numbers=[start_line],
                    confidence=confidence,
                    attack_surface=f"privileged function: {label}",
                    exploit_vector=(
                        f"Call `{fn_name}()` directly as any EOA/contract "
                        f"to {label} without authorization"
                    ),
                    raw_evidence=fn_body[:300],
                    exploit_hints={
                        "vulnerable_function": fn_name,
                        "operation": label,
                        "is_initializer": "initializ" in fn_name.lower() or "init" in fn_name.lower(),
                    }
                ))

        return findings

    def _check_unprotected_initializers(self, source, contract_name) -> list:
        findings = []

        for pattern in self.INIT_PATTERNS:
            for fn_name, fn_body, start_line in self._iter_functions(source):
                if not re.search(r'initialize|__\w+_init|^init$', fn_name, re.IGNORECASE):
                    continue

                # Check for initializer guard
                is_protected = any([
                    re.search(r'initializer\b', fn_body),
                    re.search(r'_initialized\b', source),
                    re.search(r'require.*!initialized', fn_body),
                    re.search(r'onlyOwner', fn_body),
                ])

                if not is_protected:
                    findings.append(Finding(
                        bug_class=self.BUG_CLASS,
                        severity="CRITICAL",
                        description=(
                            f"Unprotected initializer `{fn_name}` — "
                            f"proxy implementation can be re-initialized by anyone, "
                            f"potentially hijacking ownership."
                        ),
                        function_name=fn_name,
                        contract_name=contract_name,
                        line_numbers=[start_line],
                        confidence=0.85,
                        attack_surface="proxy initializer",
                        exploit_vector=(
                            f"Call `{fn_name}()` on implementation contract directly, "
                            f"set attacker as owner, self-destruct or drain."
                        ),
                        raw_evidence=fn_body[:300],
                        exploit_hints={
                            "vulnerable_function": fn_name,
                            "operation": "initializer takeover",
                            "is_initializer": True,
                        }
                    ))

        return findings

    def _check_tx_origin(self, source, contract_name) -> list:
        findings = []

        for fn_name, fn_body, start_line in self._iter_functions(source):
            if re.search(r'tx\.origin', fn_body):
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity="HIGH",
                    description=(
                        f"`{fn_name}` uses `tx.origin` for authorization — "
                        f"vulnerable to phishing: any contract called by the owner "
                        f"can impersonate them."
                    ),
                    function_name=fn_name,
                    contract_name=contract_name,
                    line_numbers=[start_line],
                    confidence=0.9,
                    attack_surface="tx.origin authentication",
                    exploit_vector=(
                        "Deploy attacker contract. Trick owner into calling it. "
                        "Attacker contract calls victim using owner's tx.origin."
                    ),
                    raw_evidence=fn_body[:300],
                    exploit_hints={
                        "vulnerable_function": fn_name,
                        "operation": "tx.origin phishing",
                    }
                ))

        return findings

    def _check_role_escalation(self, source, contract_name) -> list:
        """Detect self-grant of admin roles."""
        findings = []

        escalation_patterns = [
            (r'_setupRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*,\s*msg\.sender\s*\)',
             "self-grant of DEFAULT_ADMIN_ROLE in non-init context"),
            (r'grantRole\s*\(\s*\w+\s*,\s*msg\.sender\s*\)',
             "self-grant of role"),
        ]

        for fn_name, fn_body, start_line in self._iter_functions(source):
            if re.search(r'initialize|constructor', fn_name, re.IGNORECASE):
                continue  # Expected in constructors

            for pattern, desc in escalation_patterns:
                if re.search(pattern, fn_body):
                    has_auth = any(re.search(ap, fn_body) for ap in self.AUTH_PATTERNS)
                    if not has_auth:
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="CRITICAL",
                            description=f"`{fn_name}`: {desc} without authorization check",
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.80,
                            attack_surface="role escalation",
                            exploit_vector=f"Call `{fn_name}()` to self-grant admin role, then abuse privileges",
                            raw_evidence=fn_body[:300],
                            exploit_hints={
                                "vulnerable_function": fn_name,
                                "operation": "role escalation",
                            }
                        ))

        return findings

    def _score_confidence(self, fn_name, fn_body, label) -> float:
        confidence = 0.6

        # Higher risk operations
        if any(k in label for k in ["minting", "withdrawal", "upgrade", "ownership"]):
            confidence += 0.15

        # Public/external without modifier
        if re.search(r'\bpublic\b|\bexternal\b', fn_body[:100]):
            confidence += 0.10

        # No require at all
        if "require" not in fn_body and "modifier" not in fn_body:
            confidence += 0.10

        return min(1.0, confidence)
