"""
Integer Overflow/Underflow Detector
For pre-0.8.0 contracts without SafeMath, and unchecked{} blocks in >=0.8.0.

Real-world examples:
- BatchOverflow BEC ($900M paper loss)
- SmartMesh ($800M paper loss)
- PoWHC ($866K)
"""

import re
from .base import VulnerabilityDetector, Finding


class IntegerOverflowDetector(VulnerabilityDetector):
    BUG_CLASS = "integer_overflow"
    SEVERITY = "HIGH"

    ARITHMETIC_PATTERNS = [
        (r'\w+\s*\+=\s*\w+', "addition assignment"),
        (r'\w+\s*\*=\s*\w+', "multiplication assignment"),
        (r'\w+\s*-=\s*\w+', "subtraction assignment"),
        (r'\w+\s*\+\s*\w+', "addition"),
        (r'\w+\s*\*\s*\w+', "multiplication"),
    ]

    SAFEMATH_PATTERNS = [
        r'using\s+SafeMath',
        r'SafeMath\.\w+\(',
        r'\.add\s*\(',
        r'\.sub\s*\(',
        r'\.mul\s*\(',
        r'\.div\s*\(',
    ]

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)
            is_pre_080 = self._is_pre_080()
            has_safemath = any(re.search(p, source) for p in self.SAFEMATH_PATTERNS)

            # Pre-0.8.0 without SafeMath: HIGH risk
            if is_pre_080 and not has_safemath:
                for fn_name, fn_body, start_line in self._iter_functions(source):
                    for pattern, op in self.ARITHMETIC_PATTERNS:
                        if re.search(pattern, fn_body):
                            findings.append(Finding(
                                bug_class=self.BUG_CLASS,
                                severity="HIGH",
                                description=(
                                    f"`{fn_name}`: {op} in pre-0.8.0 contract without SafeMath. "
                                    f"Unchecked arithmetic can overflow/underflow silently."
                                ),
                                function_name=fn_name,
                                contract_name=contract_name,
                                line_numbers=[start_line],
                                confidence=0.80,
                                attack_surface=f"unprotected arithmetic: {op}",
                                exploit_vector=(
                                    f"Pass crafted values to {fn_name}() causing integer wrap, "
                                    f"e.g. uint256 max+1=0 or 0-1=uint256_max"
                                ),
                                raw_evidence=fn_body[:200],
                                exploit_hints={
                                    "vulnerable_function": fn_name,
                                    "is_pre_080": True,
                                    "overflow_type": op,
                                }
                            ))
                            break  # one finding per function

            # >=0.8.0: look for unchecked{} blocks with arithmetic
            else:
                for fn_name, fn_body, start_line in self._iter_functions(source):
                    unchecked_blocks = re.findall(r'unchecked\s*\{([^}]+)\}', fn_body, re.DOTALL)
                    for block in unchecked_blocks:
                        for pattern, op in self.ARITHMETIC_PATTERNS:
                            if re.search(pattern, block):
                                findings.append(Finding(
                                    bug_class=self.BUG_CLASS,
                                    severity="MEDIUM",
                                    description=(
                                        f"`{fn_name}`: unchecked arithmetic block — "
                                        f"{op} without overflow protection. Verify this is safe."
                                    ),
                                    function_name=fn_name,
                                    contract_name=contract_name,
                                    line_numbers=[start_line],
                                    confidence=0.55,
                                    attack_surface="unchecked{} arithmetic",
                                    exploit_vector=f"Pass extreme values to {fn_name}() to wrap integers",
                                    raw_evidence=block[:200],
                                    exploit_hints={
                                        "vulnerable_function": fn_name,
                                        "is_pre_080": False,
                                        "overflow_type": op,
                                    }
                                ))
                                break

        self._log(f"Found {len(findings)} overflow finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Flash Loan Attack Detector
Identifies contracts that make critical state decisions readable and exploitable
within a single transaction, enabling flash loan manipulation.
"""


class FlashLoanDetector(VulnerabilityDetector):
    BUG_CLASS = "flash_loan"
    SEVERITY = "CRITICAL"

    # Flash loan provider interfaces
    FLASH_PATTERNS = [
        r'flashLoan\s*\(',
        r'flashSwap\s*\(',
        r'executeOperation\s*\(',
        r'uniswapV2Call\s*\(',
        r'uniswapV3FlashCallback\s*\(',
        r'onFlashLoan\s*\(',
        r'pancakeCall\s*\(',
        r'FLASHLOAN',
    ]

    # Single-tx profit patterns
    PROFIT_PATTERNS = [
        r'getReserves.*swap|swap.*getReserves',
        r'borrow.*repay|repay.*borrow',
        r'mint.*burn|burn.*mint',
    ]

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            # Check 1: Contracts that receive flash loans but don't validate caller
            for fn_name, fn_body, start_line in self._iter_functions(source):
                is_flash_callback = any(
                    re.search(p, fn_name, re.IGNORECASE) for p in [
                        r'flashLoan', r'uniswapCall', r'pancakeCall',
                        r'executeOperation', r'onFlashLoan'
                    ]
                )

                if is_flash_callback:
                    # Should validate initiator/sender
                    has_caller_check = any([
                        re.search(r'require.*msg\.sender', fn_body),
                        re.search(r'require.*initiator', fn_body),
                        re.search(r'require.*caller', fn_body),
                        re.search(r'msg\.sender\s*==\s*\w+', fn_body),
                    ])

                    if not has_caller_check:
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="CRITICAL",
                            description=(
                                f"Flash loan callback `{fn_name}` does not validate "
                                f"`msg.sender` — anyone can call it, not just the flash "
                                f"loan pool. Enables fake flash loan to trigger callback logic."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.90,
                            attack_surface="unvalidated flash loan callback",
                            exploit_vector=(
                                f"Call `{fn_name}()` directly (without real flash loan), "
                                f"bypass repayment check, drain funds."
                            ),
                            raw_evidence=fn_body[:300],
                            exploit_hints={
                                "vulnerable_function": fn_name,
                                "operation": "fake flash loan callback",
                            }
                        ))

        self._log(f"Found {len(findings)} flash loan finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Unchecked Return Value Detector
Detects missing checks on .call(), ERC20 transfer returns, and low-level calls.

Real-world examples:
- King of the Ether ($0.3M) — unchecked send
- Multiple DeFi protocols lost funds to silent transfer failures
"""


class UncheckedReturnDetector(VulnerabilityDetector):
    BUG_CLASS = "unchecked_return"
    SEVERITY = "MEDIUM"

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            for fn_name, fn_body, start_line in self._iter_functions(source):
                # Pattern 1: .call() without checking return
                for m in re.finditer(r'(\w+)\.call\s*\{[^}]*\}\s*\([^)]*\)', fn_body):
                    call_pos = m.start()
                    context = fn_body[max(0, call_pos-5):call_pos+200]

                    if not re.search(r'bool\s+\w+\s*,\s*|require\s*\(|if\s*\(', context[:50]):
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="HIGH",
                            description=(
                                f"`{fn_name}`: `.call()` return value not checked — "
                                f"failed ETH sends silently succeed from caller's perspective, "
                                f"allowing reentrancy or stuck funds."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.80,
                            attack_surface="unchecked low-level call",
                            exploit_vector=f"Force {fn_name}() to call a reverting contract, "
                                          f"state updates proceed despite failed transfer",
                            raw_evidence=context,
                            exploit_hints={"vulnerable_function": fn_name}
                        ))

                # Pattern 2: ERC20 transfer without bool check
                for m in re.finditer(
                    r'IERC20\([^)]+\)\.(transfer|transferFrom)\s*\(', fn_body
                ):
                    call_pos = m.start()
                    context = fn_body[max(0, call_pos-5):call_pos+150]

                    if not re.search(r'require|bool\s+\w+\s*=|if\s*\(', context[:20]):
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="MEDIUM",
                            description=(
                                f"`{fn_name}`: ERC20 {m.group(1)}() return not checked — "
                                f"tokens like USDT return false instead of reverting."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.70,
                            attack_surface="unchecked ERC20 return",
                            exploit_vector="Use non-standard ERC20 that returns false to bypass accounting",
                            raw_evidence=context,
                            exploit_hints={"vulnerable_function": fn_name}
                        ))

        self._log(f"Found {len(findings)} unchecked return finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Front-Running Detector
Identifies functions vulnerable to sandwich attacks, MEV, or transaction ordering exploits.
"""


class FrontRunningDetector(VulnerabilityDetector):
    BUG_CLASS = "front_running"
    SEVERITY = "MEDIUM"

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            for fn_name, fn_body, start_line in self._iter_functions(source):
                # Pattern 1: approve + transferFrom race
                if re.search(r'\bapprove\b', fn_body) and not re.search(r'increaseAllowance|decreaseAllowance', fn_body):
                    if re.search(r'transferFrom', fn_body):
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="MEDIUM",
                            description=(
                                f"`{fn_name}`: ERC20 approve+transferFrom race condition — "
                                f"front-runner can double-spend the allowance."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.65,
                            attack_surface="approve/transferFrom race",
                            exploit_vector="Watch mempool, front-run approve tx, spend old+new allowance",
                            raw_evidence=fn_body[:300],
                            exploit_hints={"vulnerable_function": fn_name}
                        ))

                # Pattern 2: Swap without slippage protection
                if re.search(r'swap\w*\s*\(', fn_body, re.IGNORECASE):
                    has_slippage = any(re.search(p, fn_body) for p in [
                        r'amountOutMin', r'minAmount', r'minOut', r'slippage',
                        r'deadline', r'require.*amount.*>', r'require.*min'
                    ])
                    if not has_slippage:
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="HIGH",
                            description=(
                                f"`{fn_name}`: Swap with no slippage protection — "
                                f"sandwich attack possible: front-run price, execute swap at "
                                f"worse rate, back-run to profit."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=0.70,
                            attack_surface="unprotected swap",
                            exploit_vector="Sandwich: buy before victim, sell after victim tx",
                            raw_evidence=fn_body[:300],
                            exploit_hints={"vulnerable_function": fn_name}
                        ))

        self._log(f"Found {len(findings)} front-running finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Delegatecall Injection Detector
Finds dangerous delegatecall patterns where destination is attacker-controlled.

Real-world examples:
- Parity Multisig ($30M, $150M frozen)
- Furucombo ($14M)
"""


class DelegatecallDetector(VulnerabilityDetector):
    BUG_CLASS = "delegatecall"
    SEVERITY = "CRITICAL"

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            for fn_name, fn_body, start_line in self._iter_functions(source):
                # Find delegatecall
                for m in re.finditer(r'\.delegatecall\s*\(', fn_body):
                    call_pos = m.start()
                    pre_context = fn_body[max(0, call_pos-200):call_pos]

                    # Is destination user-controlled?
                    is_user_controlled = any([
                        re.search(r'msg\.sender', pre_context[-100:]),
                        re.search(r'\baddress\b.*param|param.*\baddress\b', pre_context[-100:]),
                        re.search(r'_target\b|_to\b|_impl\b|_logic\b', pre_context[-100:]),
                    ])

                    has_whitelist = any(re.search(p, fn_body) for p in [
                        r'require.*whitelist', r'isWhitelisted', r'approved\[',
                        r'trustedContracts', r'require.*==.*impl',
                    ])

                    confidence = 0.85 if is_user_controlled else 0.55
                    if has_whitelist:
                        confidence -= 0.40

                    if confidence >= 0.4:
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity="CRITICAL",
                            description=(
                                f"`{fn_name}`: delegatecall to "
                                f"{'user-controlled' if is_user_controlled else 'potentially unsafe'} "
                                f"address — attacker can execute arbitrary code in caller's storage context, "
                                f"overwriting owner, balances, or selfdestruct."
                            ),
                            function_name=fn_name,
                            contract_name=contract_name,
                            line_numbers=[start_line],
                            confidence=confidence,
                            attack_surface="delegatecall injection",
                            exploit_vector=(
                                "Pass malicious contract address, delegatecall executes attacker "
                                "code in victim storage, overwrite owner slot, drain funds."
                            ),
                            raw_evidence=fn_body[max(0,call_pos-100):call_pos+100],
                            exploit_hints={
                                "vulnerable_function": fn_name,
                                "is_user_controlled": is_user_controlled,
                            }
                        ))

        self._log(f"Found {len(findings)} delegatecall finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Storage Collision Detector
Detects proxy patterns with overlapping storage layouts.

Real-world examples:
- Audius ($6M) — storage collision via governance
"""


class StorageCollisionDetector(VulnerabilityDetector):
    BUG_CLASS = "storage_collision"
    SEVERITY = "HIGH"

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            is_proxy = bool(re.search(
                r'delegatecall|Proxy|Implementation|upgradeable', source, re.IGNORECASE
            ))

            if not is_proxy:
                continue

            # Check 1: Missing EIP-1967 storage slots
            uses_eip1967 = bool(re.search(
                r'0x360894|0xb53127|EIP1967|_IMPLEMENTATION_SLOT', source
            ))

            # Check 2: Inherited contracts with state variables
            has_state_in_proxy = bool(re.search(
                r'^\s+(address|uint|mapping|bool)\s+\w+\s*;',
                source, re.MULTILINE
            ))

            if not uses_eip1967 and has_state_in_proxy:
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity="HIGH",
                    description=(
                        f"`{contract_name}`: Proxy contract with state variables "
                        f"not using EIP-1967 storage slots — implementation state may "
                        f"collide with proxy admin slot, enabling storage manipulation."
                    ),
                    function_name=None,
                    contract_name=contract_name,
                    line_numbers=[1],
                    confidence=0.65,
                    attack_surface="proxy storage collision",
                    exploit_vector=(
                        "Overwrite proxy admin slot via colliding state variable in implementation, "
                        "take over proxy, upgrade to malicious implementation."
                    ),
                    raw_evidence=source[:400],
                    exploit_hints={
                        "operation": "storage collision",
                        "is_proxy": True,
                    }
                ))

        self._log(f"Found {len(findings)} storage collision finding(s)")
        return findings


# ──────────────────────────────────────────────────────────────────────────────


"""
Logic Flaw Detector
Catches common business logic errors: wrong math, reward manipulation,
incorrect accounting, and missing validation.

Real-world examples:
- Compound $80M — wrong price calculation
- Synthetix — sKRW infinite mint
- Saddle Finance — incorrect invariant math
"""


class LogicFlawDetector(VulnerabilityDetector):
    BUG_CLASS = "logic_flaw"
    SEVERITY = "HIGH"

    def detect(self) -> list:
        findings = []

        for filename, source in self.sources.items():
            contract_name = self._contract_name(source)

            for fn_name, fn_body, start_line in self._iter_functions(source):
                # Check 1: Division before multiplication (precision loss)
                findings.extend(
                    self._check_div_before_mul(fn_name, fn_body, start_line, contract_name)
                )

                # Check 2: Reward calculation using block.timestamp
                findings.extend(
                    self._check_timestamp_reward(fn_name, fn_body, start_line, contract_name)
                )

                # Check 3: Missing zero-address check on critical params
                findings.extend(
                    self._check_zero_address(fn_name, fn_body, start_line, contract_name)
                )

                # Check 4: Incorrect loop termination
                findings.extend(
                    self._check_loop_issues(fn_name, fn_body, start_line, contract_name)
                )

        self._log(f"Found {len(findings)} logic flaw finding(s)")
        return findings

    def _check_div_before_mul(self, fn_name, fn_body, start_line, contract_name):
        """a / b * c loses precision — should be a * c / b"""
        findings = []
        if re.search(r'\w+\s*/\s*\w+\s*\*\s*\w+', fn_body):
            if not re.search(r'1e18|1 ether|WAD|RAY|PRECISION', fn_body):
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity="MEDIUM",
                    description=(
                        f"`{fn_name}`: Division before multiplication — "
                        f"integer truncation causes precision loss. "
                        f"Could lead to zero rewards or incorrect amounts."
                    ),
                    function_name=fn_name,
                    contract_name=contract_name,
                    line_numbers=[start_line],
                    confidence=0.60,
                    attack_surface="arithmetic precision",
                    exploit_vector="Craft inputs that maximize truncation to steal dust amounts at scale",
                    raw_evidence=fn_body[:200],
                    exploit_hints={"vulnerable_function": fn_name}
                ))
        return findings

    def _check_timestamp_reward(self, fn_name, fn_body, start_line, contract_name):
        """block.timestamp in reward calc is manipulable by miners (±15s)"""
        findings = []
        if (re.search(r'block\.timestamp', fn_body) and
                re.search(r'reward|earn|yield|interest|claim', fn_body, re.IGNORECASE)):
            findings.append(Finding(
                bug_class=self.BUG_CLASS,
                severity="LOW",
                description=(
                    f"`{fn_name}`: Uses `block.timestamp` in reward calculation — "
                    f"miners can slightly manipulate timestamp to optimize reward extraction."
                ),
                function_name=fn_name,
                contract_name=contract_name,
                line_numbers=[start_line],
                confidence=0.50,
                attack_surface="timestamp manipulation",
                exploit_vector="Miner adjusts block.timestamp to claim maximum rewards per block",
                raw_evidence=fn_body[:200],
                exploit_hints={"vulnerable_function": fn_name}
            ))
        return findings

    def _check_zero_address(self, fn_name, fn_body, start_line, contract_name):
        """Missing zero-address validation on address parameters"""
        findings = []
        has_address_param = re.search(r'function\s+' + fn_name + r'\s*\([^)]*address\s+\w+', source if hasattr(self, '_current_source') else fn_body)
        has_zero_check = re.search(r'address\(0\)|!= 0x0|!= address(0)', fn_body)
        set_pattern = re.search(r'(owner|admin|treasury|fee)\s*=\s*\w+', fn_body)

        if set_pattern and not has_zero_check:
            findings.append(Finding(
                bug_class=self.BUG_CLASS,
                severity="MEDIUM",
                description=(
                    f"`{fn_name}`: Sets critical address `{set_pattern.group(1)}` "
                    f"without zero-address check — could accidentally lock contract "
                    f"or set to attacker-controlled address."
                ),
                function_name=fn_name,
                contract_name=contract_name,
                line_numbers=[start_line],
                confidence=0.55,
                attack_surface="missing validation",
                exploit_vector=f"Call {fn_name}(address(0)) to permanently brick protocol",
                raw_evidence=fn_body[:200],
                exploit_hints={"vulnerable_function": fn_name}
            ))
        return findings

    def _check_loop_issues(self, fn_name, fn_body, start_line, contract_name):
        """Unbounded loops can cause DoS via gas exhaustion"""
        findings = []
        if re.search(r'for\s*\(', fn_body):
            # Loop over user-controlled array
            if re.search(r'\.length\b', fn_body) and not re.search(r'MAX_\w+|maxLen|limit', fn_body):
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity="MEDIUM",
                    description=(
                        f"`{fn_name}`: Unbounded loop over dynamic array — "
                        f"attacker can bloat array to cause OOG revert, "
                        f"permanently DoSing this function."
                    ),
                    function_name=fn_name,
                    contract_name=contract_name,
                    line_numbers=[start_line],
                    confidence=0.60,
                    attack_surface="unbounded loop",
                    exploit_vector="Push many items to the array, then call function to OOG-DoS it",
                    raw_evidence=fn_body[:200],
                    exploit_hints={"vulnerable_function": fn_name}
                ))
        return findings
