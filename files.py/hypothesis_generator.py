"""
Attack Hypothesis Generator
The core differentiator: generates structured, non-obvious attack hypotheses
from vulnerability findings and contract source analysis.

Two modes:
1. Heuristic: rule-based templates from findings (fast, no API)
2. LLM-guided: uses Claude to reason about counter-intuitive attack paths
"""

import os
import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackHypothesis:
    """A structured, actionable attack hypothesis."""
    bug_class: str
    description: str                     # Human readable
    vulnerable_function: str
    contract_name: str
    attack_type: str                     # "direct" | "flash_loan" | "reentrancy" | "sandwich"
    requires_flash_loan: bool = False
    requires_multiple_txs: bool = False
    attacker_setup: list = field(default_factory=list)  # Pre-conditions
    attack_steps: list = field(default_factory=list)    # Ordered steps
    success_condition: str = ""                          # What proves the exploit worked
    profit_mechanism: str = ""
    confidence: float = 0.7
    llm_generated: bool = False
    raw_hints: dict = field(default_factory=dict)


# ── Heuristic Templates ───────────────────────────────────────────────────────

REENTRANCY_TEMPLATE = {
    "attack_type": "reentrancy",
    "requires_flash_loan": False,
    "attacker_setup": [
        "Deploy AttackerContract with malicious receive()/fallback()",
        "Fund AttackerContract with minimum deposit amount",
    ],
    "attack_steps": [
        "AttackerContract.attack() calls victim.{fn}()",
        "Victim sends ETH to AttackerContract",
        "AttackerContract.receive() re-enters victim.{fn}()",
        "Loop until victim balance exhausted",
        "AttackerContract.withdraw() extracts profit",
    ],
    "success_condition": "address(victim).balance == 0 || attacker profit > 0",
    "profit_mechanism": "Drain ETH or tokens before balance update",
}

ACCESS_CONTROL_TEMPLATE = {
    "attack_type": "direct",
    "requires_flash_loan": False,
    "attacker_setup": [
        "Any EOA — no special setup required",
    ],
    "attack_steps": [
        "Call victim.{fn}() directly as any address",
        "Execute privileged operation (mint/withdraw/upgrade)",
        "Extract value or take ownership",
    ],
    "success_condition": "Privileged action executed without authorization",
    "profit_mechanism": "Mint unbacked tokens, drain treasury, or hijack ownership",
}

ORACLE_TEMPLATE = {
    "attack_type": "flash_loan",
    "requires_flash_loan": True,
    "attacker_setup": [
        "Deploy AttackerContract",
        "Identify flash loan source (Aave/dYdX/Uniswap)",
    ],
    "attack_steps": [
        "Flash borrow large amount of token X",
        "Swap aggressively to manipulate AMM price/reserves",
        "Call victim.{fn}() with distorted price",
        "Extract profit (borrow against inflated collateral or liquidate at wrong price)",
        "Restore price, repay flash loan + fee",
    ],
    "success_condition": "Attacker profit after flash loan repayment > 0",
    "profit_mechanism": "Exploit price discrepancy between manipulation and victim's stale price",
}

OVERFLOW_TEMPLATE = {
    "attack_type": "direct",
    "requires_flash_loan": False,
    "attacker_setup": ["Calculate wrap value: (2**256) - currentValue + 1"],
    "attack_steps": [
        "Call victim.{fn}() with crafted overflow value",
        "Integer wraps to unexpected small/large value",
        "Exploit wrong accounting to mint tokens or withdraw excess",
    ],
    "success_condition": "Token balance or ETH balance inconsistent post-overflow",
    "profit_mechanism": "Mint arbitrary tokens or bypass balance checks",
}

FLASH_LOAN_CALLBACK_TEMPLATE = {
    "attack_type": "direct",
    "requires_flash_loan": False,
    "attacker_setup": ["Deploy AttackerContract"],
    "attack_steps": [
        "Call victim.{fn}() directly (no actual flash loan)",
        "Bypass caller validation check",
        "Execute callback logic (transfer, withdraw, mint)",
        "Drain funds without repaying any loan",
    ],
    "success_condition": "Funds extracted without flash loan repayment",
    "profit_mechanism": "Free token/ETH drain via unprotected callback",
}

DELEGATECALL_TEMPLATE = {
    "attack_type": "direct",
    "requires_flash_loan": False,
    "attacker_setup": ["Deploy MaliciousImpl contract with selfdestruct or storage overwrite"],
    "attack_steps": [
        "Call victim.{fn}(address(MaliciousImpl), ...)",
        "Victim delegatecalls into MaliciousImpl",
        "MaliciousImpl overwrites owner slot (slot 0) to attacker",
        "Now call any onlyOwner function as attacker",
        "Drain funds or upgrade to backdoored implementation",
    ],
    "success_condition": "owner() == attacker || funds drained",
    "profit_mechanism": "Full contract takeover via storage overwrite",
}

BUG_TO_TEMPLATE = {
    "reentrancy":          REENTRANCY_TEMPLATE,
    "access_control":      ACCESS_CONTROL_TEMPLATE,
    "oracle_manipulation": ORACLE_TEMPLATE,
    "integer_overflow":    OVERFLOW_TEMPLATE,
    "flash_loan":          FLASH_LOAN_CALLBACK_TEMPLATE,
    "unchecked_return":    ACCESS_CONTROL_TEMPLATE,  # similar pattern
    "front_running":       ORACLE_TEMPLATE,           # similar setup
    "delegatecall":        DELEGATECALL_TEMPLATE,
    "storage_collision":   DELEGATECALL_TEMPLATE,
    "logic_flaw":          OVERFLOW_TEMPLATE,
}


class HypothesisGenerator:
    def __init__(self, project, findings, use_llm=False, verbose=False):
        self.project = project
        self.findings = findings
        self.use_llm = use_llm
        self.verbose = verbose

    def generate(self) -> list:
        """Generate hypotheses from findings."""
        hypotheses = []

        # Heuristic hypotheses from findings
        for finding in self.findings:
            h = self._heuristic_hypothesis(finding)
            if h:
                hypotheses.append(h)

        # LLM-augmented reasoning (if enabled)
        if self.use_llm and self.findings:
            llm_hypotheses = self._llm_hypotheses()
            # Merge, avoiding exact duplicates
            existing_fns = {h.vulnerable_function for h in hypotheses}
            for h in llm_hypotheses:
                if h.vulnerable_function not in existing_fns or h.llm_generated:
                    hypotheses.append(h)

        # If no findings, generate blind hypotheses
        if not hypotheses:
            hypotheses = self._blind_hypotheses()

        # Sort by confidence
        hypotheses.sort(key=lambda h: -h.confidence)

        if self.verbose:
            print(f"[hypothesis] Generated {len(hypotheses)} hypotheses")

        return hypotheses

    def _heuristic_hypothesis(self, finding) -> Optional[AttackHypothesis]:
        """Convert a finding into an attack hypothesis using templates."""
        template = BUG_TO_TEMPLATE.get(finding.bug_class)
        if not template:
            return None

        fn = finding.function_name or "unknown"

        steps = [s.format(fn=fn) for s in template["attack_steps"]]

        return AttackHypothesis(
            bug_class=finding.bug_class,
            description=finding.description,
            vulnerable_function=fn,
            contract_name=finding.contract_name or "Target",
            attack_type=template["attack_type"],
            requires_flash_loan=template["requires_flash_loan"],
            attacker_setup=template["attacker_setup"],
            attack_steps=steps,
            success_condition=template["success_condition"],
            profit_mechanism=template["profit_mechanism"],
            confidence=finding.confidence,
            raw_hints=finding.exploit_hints or {},
        )

    def _llm_hypotheses(self) -> list:
        """Use Claude API to generate counter-intuitive attack hypotheses."""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

            # Build context from sources
            source_excerpt = ""
            for name, src in self.project.raw_sources.items():
                source_excerpt += f"\n\n// === {name} ===\n{src[:3000]}"

            findings_summary = "\n".join([
                f"- [{f.severity}] {f.bug_class}: {f.description}"
                for f in self.findings[:5]
            ])

            prompt = f"""You are an elite smart contract security researcher.
Analyze this Solidity contract and the detected vulnerabilities.
Generate 2-3 NON-OBVIOUS, counter-intuitive attack hypotheses that a standard auditor might miss.

Detected vulnerabilities:
{findings_summary}

Contract source (excerpt):
```solidity{source_excerpt[:4000]}```

For each attack path, respond in strict JSON array format:
[
  {{
    "bug_class": "reentrancy|access_control|oracle_manipulation|...",
    "description": "...",
    "vulnerable_function": "functionName",
    "contract_name": "ContractName",
    "attack_type": "direct|flash_loan|reentrancy|sandwich",
    "requires_flash_loan": false,
    "attacker_setup": ["step1", "step2"],
    "attack_steps": ["step1", "step2", "step3"],
    "success_condition": "...",
    "profit_mechanism": "...",
    "confidence": 0.75,
    "reasoning": "why this is non-obvious"
  }}
]

Focus on:
- Cross-function reentrancy (not just single-function)
- Read-only reentrancy (balances used in view functions)
- Combining two medium-severity issues into a critical exploit
- Edge cases in tokenomics math
- State inconsistencies across multiple calls

Respond ONLY with the JSON array."""

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            text = response.content[0].text.strip()
            text = re.sub(r'^```json\s*|```\s*$', '', text)
            data = json.loads(text)

            hypotheses = []
            for item in data:
                h = AttackHypothesis(
                    bug_class=item.get("bug_class", "unknown"),
                    description=item.get("description", ""),
                    vulnerable_function=item.get("vulnerable_function", "unknown"),
                    contract_name=item.get("contract_name", "Target"),
                    attack_type=item.get("attack_type", "direct"),
                    requires_flash_loan=item.get("requires_flash_loan", False),
                    attacker_setup=item.get("attacker_setup", []),
                    attack_steps=item.get("attack_steps", []),
                    success_condition=item.get("success_condition", ""),
                    profit_mechanism=item.get("profit_mechanism", ""),
                    confidence=item.get("confidence", 0.6),
                    llm_generated=True,
                )
                hypotheses.append(h)

            if self.verbose:
                print(f"[hypothesis] LLM generated {len(hypotheses)} additional hypotheses")

            return hypotheses

        except Exception as e:
            if self.verbose:
                print(f"[hypothesis] LLM generation failed: {e}")
            return []

    def _blind_hypotheses(self) -> list:
        """Generate generic hypotheses when no findings exist."""
        contract_name = "Target"
        for src in self.project.raw_sources.values():
            m = re.search(r'contract\s+(\w+)', src)
            if m:
                contract_name = m.group(1)
                break

        return [
            AttackHypothesis(
                bug_class="reentrancy",
                description="Blind reentrancy attempt on any payable withdrawal function",
                vulnerable_function="withdraw",
                contract_name=contract_name,
                attack_type="reentrancy",
                attacker_setup=["Deploy AttackerContract"],
                attack_steps=["Call withdraw()", "Re-enter in receive()"],
                success_condition="attacker.balance > initial_balance",
                profit_mechanism="Drain ETH via reentrancy",
                confidence=0.35,
            ),
            AttackHypothesis(
                bug_class="access_control",
                description="Blind access control test on admin functions",
                vulnerable_function="setOwner",
                contract_name=contract_name,
                attack_type="direct",
                attacker_setup=["Any EOA"],
                attack_steps=["Call any privileged function directly"],
                success_condition="Privileged action succeeded",
                profit_mechanism="Contract takeover",
                confidence=0.30,
            ),
        ]
