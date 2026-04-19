# SmartExploit — Autonomous Smart Contract Exploit Engine

> **"Refuses to stop until it breaks the contract or exhausts all intelligent attack paths."**

SmartExploit is a zero-config, autonomous smart contract exploit generation system. It takes a raw Solidity contract and produces **executable proof-of-exploit** — not just detection flags.

---

## Architecture

```
Input Contract (.sol)
       │
       ▼
┌─────────────────────┐
│  1. Input Normalizer │  → Foundry project (auto compiler, deps)
└─────────────────────┘
       │
       ▼
┌─────────────────────────┐
│  2. Vulnerability Analyzer│  → 10 bug classes, ranked findings
└─────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│  3. Hypothesis Generator      │  → Adversarial attack paths (+ LLM option)
└──────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│  4. Exploit Generator + Execution Loop│  → Foundry tests, mutate on failure
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────┐
│  5. Synthesizer   │  → Exploit proof: steps, trace, profit, patch
└──────────────────┘
```

---

## The 10 Critical Bug Classes

| # | Bug Class | Real Losses | Severity |
|---|-----------|-------------|----------|
| 1 | **Reentrancy** (CEI violation) | $60M DAO, $80M Fei/Rari | CRITICAL |
| 2 | **Access Control Bypass** | $611M Poly Network, $625M Ronin | CRITICAL |
| 3 | **Oracle/Price Manipulation** | $116M Mango, $34M Harvest | CRITICAL |
| 4 | **Integer Overflow/Underflow** | $900M BatchOverflow (BEC) | HIGH |
| 5 | **Flash Loan Attack** | $130M Euler Finance | CRITICAL |
| 6 | **Unchecked Return Values** | Numerous ERC20 failures | MEDIUM |
| 7 | **Front-Running / MEV** | Sandwich attacks (daily losses) | HIGH |
| 8 | **Delegatecall Injection** | $30M Parity, $14M Furucombo | CRITICAL |
| 9 | **Storage Collision** | $6M Audius | HIGH |
| 10 | **Logic Flaw** | $80M Compound, Synthetix | HIGH |

---

## Installation

### Prerequisites
```bash
# 1. Foundry (Forge) — required for real execution
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 2. Python 3.10+
python3 --version

# 3. Install Python deps
pip install -r requirements.txt
```

### Quick Start
```bash
# Clone / set up
cd smart-exploit

# Run against a single contract
python main.py examples/vulnerable_contracts/VulnerableVault.sol

# Run with LLM hypothesis generation (requires Anthropic API key)
export ANTHROPIC_API_KEY=sk-ant-...
python main.py contracts/MyToken.sol --llm

# Run with verbose output + specific bug classes
python main.py contracts/DeFi.sol --bugs reentrancy access_control oracle --verbose

# Run against a directory of contracts
python main.py contracts/ --output ./audit_results --max-iter 5
```

---

## CLI Reference

```
python main.py <contract_path> [options]

Arguments:
  contract          Path to .sol file or directory

Options:
  --output, -o      Output directory (default: ./output)
  --max-iter, -m    Max mutation attempts per hypothesis (default: 3)
  --llm             Enable LLM-guided hypothesis generation
  --verbose, -v     Show detailed execution output
  --bugs            Target specific bug classes (default: all)
                    Choices: reentrancy access_control oracle integer_overflow
                             flash_loan unchecked_return front_running
                             delegatecall storage_collision logic_flaw
```

---

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║         SmartExploit — Autonomous Exploit Engine          ║
║    "Refuses to stop until the contract breaks."           ║
╚═══════════════════════════════════════════════════════════╝

─────────────── Phase 1: Input Normalization ────────────────
✓ Foundry project created: ./output/foundry_project
✓ Compiler: solc 0.8.0
✓ Contracts: VulnerableVault.sol

─────────────── Phase 2: Static Vulnerability Analysis ──────
┌──────────────────────────────────────────────────────────────────────┐
│ Bug Class         │ Severity │ Function    │ Description    │ Confidence│
├──────────────────────────────────────────────────────────────────────┤
│ reentrancy        │ CRITICAL │ withdraw    │ CEI violation  │ 95%       │
│ access_control    │ CRITICAL │ mint        │ No auth check  │ 90%       │
│ access_control    │ HIGH     │ emergencyW… │ No auth check  │ 85%       │
│ logic_flaw        │ MEDIUM   │ calculateR… │ Div before mul │ 60%       │
└──────────────────────────────────────────────────────────────────────┘

─────────────── Phase 3: Adversarial Hypothesis Generation ──
✓ Generated 4 attack hypotheses
  → [reentrancy]       CEI violation in withdraw(): ETH sent before balance zeroed
  → [access_control]   Unprotected mint(): any caller can mint unlimited tokens
  → [access_control]   Unprotected emergencyWithdraw(): any caller drains ETH

─────────────── Phase 4: Exploit Synthesis & Execution Loop ─
Attempt 1/4: CEI violation in withdraw()...
  ✓ EXPLOIT SUCCEEDED!

╔══════════════════════ ⚡ EXPLOIT PROOF ══════════════════════╗
║ EXPLOIT TYPE: REENTRANCY                                      ║
║                                                               ║
║ Attack Steps:                                                 ║
║   1. [Setup] Deploy AttackerContract with malicious receive() ║
║   2. [Setup] Fund AttackerContract with 1 ETH                ║
║   3. [Attack] Call victim.withdraw()                          ║
║   4. [Attack] Victim sends ETH → triggers receive()          ║
║   5. [Attack] Re-enter withdraw() 10 times                   ║
║   6. [Proven] [HIT] 10 ETH drained from vault               ║
║                                                               ║
║ Result:    Attacker profit: 9 ETH                             ║
║                                                               ║
║ Patch: Move state updates BEFORE external calls (CEI) +      ║
║        add ReentrancyGuard                                    ║
╚═══════════════════════════════════════════════════════════════╝

─────────────── Final Report ────────────────────────────────
Bugs Detected:   4
Exploits Proven: 2
Total Iterations: 4

⚠  2 working exploit(s) found! Contract is VULNERABLE.

Full report saved: ./output/exploit_report.json
```

---

## Output Files

```
output/
├── exploit_report.json          # Machine-readable full report
└── foundry_project/
    ├── src/
    │   └── VulnerableVault.sol  # Original contract
    └── test/
        ├── Exploit_reentrancy_withdraw.t.sol
        └── Exploit_access_control_mint.t.sol
```

---

## How the Iteration Loop Works

```
for each hypothesis:
    generate exploit contract
    for attempt in range(max_iterations):
        run forge test
        if PASS:
            → output exploit proof ✓ DONE
        else:
            → mutate strategy (depth, values, entry point)
            → retry
    if exhausted:
        → mark as "confidence too low"
```

Mutation strategies:
1. Increase reentrancy depth (10 → 20 → 50)
2. Increase flash loan amounts
3. Change entry function (withdraw → claim → redeem)
4. Add ERC20 approvals before attack
5. Adjust ETH values

---

## LLM Integration

When `--llm` is set, the Hypothesis Generator calls Claude with:
- Full contract source
- Static analysis findings
- Request for **counter-intuitive** attack hypotheses

Claude is prompted to find:
- **Cross-function reentrancy** (not just single function)
- **Read-only reentrancy** (balanceof in view used in decisions)
- **Combining two medium issues** into one critical exploit
- **Edge cases in tokenomics math**

The LLM guides — it does not execute. All execution is deterministic Foundry.

---

## Adding New Detectors

```python
# src/detectors/my_new_bug.py
from .base import VulnerabilityDetector, Finding

class MyNewBugDetector(VulnerabilityDetector):
    BUG_CLASS = "my_new_bug"
    SEVERITY = "HIGH"

    def detect(self) -> list:
        findings = []
        for filename, source in self.sources.items():
            # ... your detection logic
            findings.append(Finding(
                bug_class=self.BUG_CLASS,
                severity=self.SEVERITY,
                description="...",
                function_name="...",
                confidence=0.8,
                exploit_hints={"vulnerable_function": "..."},
            ))
        return findings

# Register in src/detectors/__init__.py
from .my_new_bug import MyNewBugDetector
ALL_DETECTORS["my_new_bug"] = MyNewBugDetector
```

---

## Validation Targets

Test against these known-vulnerable contracts:
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/) — 15 challenges
- [Capture the Ether](https://capturetheether.com/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)
- Historical exploits: DAO, Parity, Harvest, Cream

**MVP success criteria**: 3–4 proven exploits out of 10 known-vulnerable contracts.

---

## Security Note

This tool is designed for **security research, bug bounty programs, and defensive auditing only**.
Always obtain explicit written permission before testing contracts you do not own.
Never use against mainnet contracts without authorization.

---

## Stack

| Component | Technology |
|-----------|-----------|
| Execution sandbox | Foundry (forge test) |
| Static analysis | Regex + lightweight AST |
| LLM reasoning | Anthropic Claude (optional) |
| Orchestration | Python 3.10+ |
| Output | Rich terminal + JSON |
