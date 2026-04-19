"""
Exploit Synthesizer
Converts a successful execution result into a structured, human-readable
exploit proof with: attack steps, transaction sequence, profit, and patch.
"""

from dataclasses import dataclass


PATCH_RECOMMENDATIONS = {
    "reentrancy": {
        "short": "Move state updates BEFORE external calls (CEI pattern) and add ReentrancyGuard",
        "code": """// FIX 1: CEI Pattern (Checks-Effects-Interactions)
// WRONG:
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}("");  // ← external call first
    require(ok);
    balances[msg.sender] = 0;  // ← state update AFTER (vulnerable!)
}

// CORRECT:
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;  // ← state update FIRST
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}

// FIX 2: Import OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Vault is ReentrancyGuard {
    function withdraw() external nonReentrant { ... }
}"""
    },

    "access_control": {
        "short": "Add onlyOwner/onlyRole modifier or explicit msg.sender check",
        "code": """// FIX: Use OpenZeppelin AccessControl or Ownable
import "@openzeppelin/contracts/access/Ownable.sol";
contract Target is Ownable {
    function sensitiveFunction() external onlyOwner {
        // Only owner can call this
    }
}

// For initializers (proxy patterns):
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
contract Target is Initializable {
    function initialize(address _owner) external initializer {
        // initializer modifier prevents re-initialization
        owner = _owner;
    }
}"""
    },

    "oracle_manipulation": {
        "short": "Use TWAP instead of spot price, or use Chainlink with staleness check",
        "code": """// FIX 1: Uniswap V3 TWAP (time-weighted average price)
function getTWAP(address pool, uint32 twapInterval) internal view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;  // e.g. 1800 = 30 minutes
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickDiff / int56(uint56(twapInterval)));
    return TickMath.getSqrtRatioAtTick(avgTick);
}

// FIX 2: Chainlink with staleness check
function getPrice() internal view returns (int256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= MAX_STALENESS, "Stale price");
    return price;
}"""
    },

    "integer_overflow": {
        "short": "Use Solidity >=0.8.0 (built-in overflow checks) or SafeMath library",
        "code": """// FIX 1: Upgrade to Solidity 0.8.x (overflow reverts automatically)
pragma solidity ^0.8.0;

// FIX 2: If staying on <0.8.0, use SafeMath
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
contract Safe {
    using SafeMath for uint256;
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a.add(b);  // reverts on overflow
    }
}

// FIX 3: Use unchecked{} only for gas optimization in provably safe math
unchecked {
    // Only here if you've PROVEN this cannot overflow
    i++;
}"""
    },

    "flash_loan": {
        "short": "Validate msg.sender in flash loan callbacks — must be the trusted pool",
        "code": """// FIX: Validate that caller is the known flash loan pool
address private constant AAVE_POOL = 0x...;
address private _flashInitiator;

function executeOperation(..., address initiator, ...) external returns (bool) {
    require(msg.sender == AAVE_POOL, "Untrusted caller");
    require(initiator == address(this), "Untrusted initiator");
    // ... rest of callback
}

// Also add reentrancy guard on the initiating function
function flashLoan(...) external nonReentrant { ... }"""
    },

    "unchecked_return": {
        "short": "Always check return values from .call() and use SafeERC20 for token transfers",
        "code": """// FIX 1: Check .call() return value
(bool success, bytes memory data) = recipient.call{value: amount}("");
require(success, "ETH transfer failed");

// FIX 2: Use SafeERC20 for ERC20 transfers (handles non-standard returns)
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransfer(recipient, amount);
token.safeTransferFrom(sender, recipient, amount);"""
    },

    "front_running": {
        "short": "Add slippage parameters, deadlines, and use commit-reveal schemes",
        "code": """// FIX 1: Add minimum output and deadline to swaps
function swap(
    uint256 amountIn,
    uint256 amountOutMin,   // ← slippage protection
    uint256 deadline        // ← MEV protection
) external {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = _swap(amountIn);
    require(amountOut >= amountOutMin, "Slippage exceeded");
}

// FIX 2: Use increaseAllowance instead of approve
token.increaseAllowance(spender, additionalAmount);  // atomic, no race"""
    },

    "delegatecall": {
        "short": "Never delegatecall to user-controlled addresses — whitelist trusted implementations",
        "code": """// FIX: Whitelist trusted implementations
mapping(address => bool) public trustedImplementations;

function execute(address impl, bytes calldata data) external {
    require(trustedImplementations[impl], "Untrusted implementation");
    (bool ok,) = impl.delegatecall(data);
    require(ok, "Delegatecall failed");
}

// For proxy patterns: use EIP-1967 admin slot
bytes32 private constant IMPL_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;"""
    },

    "storage_collision": {
        "short": "Use EIP-1967 storage slots and avoid state variables in proxy contracts",
        "code": """// FIX: Use EIP-1967 unstructured storage slots
bytes32 private constant IMPLEMENTATION_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
bytes32 private constant ADMIN_SLOT =
    0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

function _getImplementation() internal view returns (address impl) {
    assembly { impl := sload(IMPLEMENTATION_SLOT) }
}

// Use OpenZeppelin TransparentUpgradeableProxy or UUPS:
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";"""
    },

    "logic_flaw": {
        "short": "Fix arithmetic order, add input validation, use fixed-point math libraries",
        "code": """// FIX 1: Multiplication before division (prevent precision loss)
// WRONG:  (amount / totalSupply) * price   ← truncates early
// CORRECT: (amount * price) / totalSupply  ← maintains precision

// FIX 2: Use fixed-point math for financial calculations
import "@prb/math/PRBMath.sol";
uint256 result = PRBMath.mulDiv(amount, price, 1e18);

// FIX 3: Add zero-address checks
function setOwner(address _owner) external onlyOwner {
    require(_owner != address(0), "Zero address");
    owner = _owner;
}

// FIX 4: Cap loop iterations
uint256 constant MAX_ITERATIONS = 100;
for (uint i = 0; i < Math.min(array.length, MAX_ITERATIONS); i++) { ... }"""
    },
}


@dataclass
class ExploitReport:
    bug_class: str
    steps: list
    result: str
    profit: str
    patch: str
    patch_code: str
    severity: str
    tx_trace: str
    logs: list


class ExploitSynthesizer:
    def __init__(self, hypothesis, execution_result, verbose=False):
        self.hypothesis = hypothesis
        self.result = execution_result
        self.verbose = verbose

    def synthesize(self) -> dict:
        """Produce the final exploit proof report."""
        h = self.hypothesis
        r = self.result

        # Build attack steps narrative
        steps = self._build_steps()

        # Determine profit description
        profit = self._extract_profit(r.logs)

        # Get patch
        patch_info = PATCH_RECOMMENDATIONS.get(h.bug_class, {
            "short": "Review and add appropriate authorization and validation",
            "code": "// Consult OpenZeppelin security patterns"
        })

        # Build result summary
        result_summary = "Exploit executed successfully. "
        for log in r.logs:
            if "[HIT]" in log or "[CRITICAL]" in log or "SUCCEEDED" in log:
                result_summary += log + " "

        report = {
            "bug_class": h.bug_class.replace("_", " ").upper(),
            "steps": steps,
            "result": result_summary.strip(),
            "profit": profit,
            "patch": patch_info["short"],
            "patch_code": patch_info["code"],
            "severity": "CRITICAL" if h.confidence > 0.7 else "HIGH",
            "tx_trace": r.tx_trace[:500] if r.tx_trace else "See forge output",
            "logs": r.logs,
            "gas_used": r.gas_used,
        }

        if self.verbose:
            print(f"[synthesizer] Report built for {h.bug_class}")

        return report

    def _build_steps(self) -> list:
        """Combine hypothesis steps with execution evidence."""
        h = self.hypothesis
        steps = []

        # Setup phase
        for s in h.attacker_setup:
            steps.append(f"[Setup] {s}")

        # Attack phase
        for s in h.attack_steps:
            steps.append(f"[Attack] {s}")

        # Flash loan note
        if h.requires_flash_loan:
            steps.insert(len(h.attacker_setup), "[Flash Loan] Borrow capital from Aave/dYdX/Uniswap")
            steps.append("[Flash Loan] Repay principal + fee")

        # Evidence from logs
        for log in self.result.logs:
            if "[HIT]" in log:
                steps.append(f"[Proven] {log}")

        return steps

    def _extract_profit(self, logs: list) -> str:
        """Extract profit info from execution logs."""
        for log in logs:
            if "profit" in log.lower() or "drained" in log.lower() or "ETH" in log:
                return log
        return "Unauthorized access / state manipulation achieved"
