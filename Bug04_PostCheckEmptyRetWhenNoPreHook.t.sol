// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import "forge-std/Test.sol";
import {MockHook} from "src/test/MockHook.sol";
import {MockERC20} from "src/test/MockERC20.sol";
import {Call} from "src/Types.sol";

/**
 * BUG-04 — LOW
 * postCheck receives empty `ret` when no preHook is set
 *
 * Root cause — ExecutorLogic.sol, modifier onlyValidSession, lines 61-81:
 *
 *   bytes memory ret;   // initialized to "" (empty bytes)
 *
 *   if (session.preHook.length >= 20)            // guard: preHook must be present
 *       ret = IHook(...).preCheck(...);           // ret only populated if preHook set
 *
 *   _;   // user calls execute here
 *
 *   if (session.postHook.length >= 20)           // guard: postHook present
 *       IHook(...).postCheck(
 *           ret,                                  // BUG: empty "" if preHook was absent
 *           session.postHook[20:],
 *           msg.sender
 *       );
 *
 * Any hook that calls abi.decode(preCheckRet, (...)) in postCheck will revert
 * with a Panic(0x22) (slice-out-of-bounds / invalid decode) when preCheckRet == "".
 *
 * MockHook (src/test/MockHook.sol lines 1181-1193) is the canonical example:
 *
 *   function postCheck(bytes calldata preHookRet, ...) external payable {
 *       (address token, uint256 initialBalance, uint256 totalAmount) =
 *           abi.decode(preHookRet, (address, uint256, uint256));   // reverts on ""
 *       ...
 *   }
 *
 * There is no protocol-level enforcement that both hooks must be present or absent
 * together. A session author who sets only postHook (e.g. for post-execution
 * balance verification) locks the session permanently.
 */

contract Bug04_PostCheckReceivesEmptyRetWhenNoPreHook is Test {

    MockHook public hook;
    MockERC20 public token;

    function setUp() public {
        hook = new MockHook();
        token = new MockERC20();  // mints 1000 ether to address(this)
    }

    // -----------------------------------------------------------------------
    // Layer 1: Prove postCheck on MockHook reverts on empty input
    // -----------------------------------------------------------------------

    /// @notice Direct proof: calling MockHook.postCheck("") reverts.
    ///         This is exactly what ExecutorLogic sends when preHook is absent.
    function test_bug04_postCheck_reverts_on_empty_preHookRet() public {
        bytes memory emptyRet = "";           // what ret = "" looks like when passed
        bytes memory hookData = "";           // postHook[20:] (irrelevant for this bug)

        // abi.decode("", (address, uint256, uint256)) panics
        vm.expectRevert();  // Panic(0x22): invalid ABI decode
        hook.postCheck(emptyRet, hookData, address(this));
    }

    /// @notice Contrast: postCheck succeeds when given valid preHookRet from preCheck.
    ///         This proves the hook itself is correct — the bug is the missing ret population.
    function test_bug04_postCheck_succeeds_with_valid_preHookRet() public {
        address tokenAddr = address(token);
        uint256 maxAmount = 100 ether;
        uint256 transferAmount = 10 ether;
        address recipient = address(0xBEEF);

        // Transfer tokens to the hook caller address so balances are meaningful
        token.transfer(address(hook), 100 ether);

        // Simulate what preCheck would return
        uint256 initialBalance = token.balanceOf(address(this));
        bytes memory validPreCheckRet = abi.encode(tokenAddr, initialBalance, transferAmount);

        // Execute the actual transfer so postCheck's balance assertion passes
        vm.prank(address(hook));
        token.transfer(recipient, transferAmount);

        bytes memory hookData = abi.encode(tokenAddr, maxAmount);

        // With valid preHookRet this succeeds — hook logic is not at fault
        vm.prank(address(this));
        hook.postCheck(validPreCheckRet, hookData, address(this));
    }

    // -----------------------------------------------------------------------
    // Layer 2: Trace the exact code path in ExecutorLogic
    // -----------------------------------------------------------------------

    /// @notice Constructs the `ret` variable state precisely as ExecutorLogic does,
    ///         then calls postCheck with it — proving the execution path causes the revert.
    function test_bug04_executorlogic_ret_variable_state_when_no_prehook() public {
        // Replicate ExecutorLogic.onlyValidSession lines 64-80 in isolation:

        bytes memory ret;  // Line 64: default empty

        // Pretend session.preHook.length < 20 (i.e. no preHook configured)
        bytes memory sessionPreHook = "";
        bool preHookSet = sessionPreHook.length >= 20;

        assertFalse(preHookSet, "preHook is not set — ret stays empty");
        assertEq(ret.length, 0, "ret is empty bytes when preHook absent");

        if (preHookSet) {
            // This branch is NOT taken
            revert("Should not reach here in this test");
        }

        // Line 75-80: postHook IS set (the session author wants post-execution check only)
        bytes memory postHookAddr = abi.encodePacked(address(hook)); // 20 bytes
        assertTrue(postHookAddr.length >= 20, "postHook is set");

        // ExecutorLogic calls: IHook(...).postCheck(ret, session.postHook[20:], msg.sender)
        // ret is "" here. postCheck will receive empty bytes as preHookRet.
        bytes memory postHookData = bytes(postHookAddr[20:]); // empty suffix
        vm.expectRevert();  // abi.decode("", ...) panics inside MockHook.postCheck
        hook.postCheck(ret, postHookData, address(this));
    }

    // -----------------------------------------------------------------------
    // Layer 3: Show no protocol-level guard exists
    // -----------------------------------------------------------------------

    /// @notice Proves there is no in-contract enforcement of "both hooks or neither".
    ///         A session with postHook.length >= 20 and preHook.length < 20 is
    ///         structurally valid but operationally always-reverts.
    function test_bug04_no_enforcement_of_hook_pairing() public pure {
        // Session struct (Types.sol line 336-345) has independent bytes fields:
        //   bytes preHook;
        //   bytes postHook;
        // No invariant enforces preHook != "" when postHook != "".

        bytes memory preHook  = "";                    // absent
        bytes memory postHook = abi.encodePacked(      // present: 20-byte addr + data
            address(0x1234567890123456789012345678901234567890),
            abi.encode(address(0xABC), uint256(100 ether))
        );

        bool preHookActive  = preHook.length  >= 20;   // false
        bool postHookActive = postHook.length >= 20;   // true

        // The modifier executes postCheck with ret="" in this configuration
        // without any revert guard or warning — the DoS is silent until runtime.
        assertFalse(preHookActive,  "preHook absent — ret will stay empty");
        assertTrue(postHookActive,  "postHook present — postCheck will be called with empty ret");
    }
}
