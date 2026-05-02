// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import "forge-std/Test.sol";
import {Storage} from "src/Storage.sol";
import {WalletCoreLib} from "src/lib/WalletCoreLib.sol";
import {Errors} from "src/lib/Errors.sol";

/**
 * BUG-01 — HIGH
 * Storage.validateSession: address(0) never skips validator check
 *
 * NatSpec at Storage.sol line 316:
 *   @param validator The validator address (0x0 to skip validator check)
 *
 * Reality: validateSession unconditionally calls validateValidator(validator).
 * validateValidator passes only address(1) (SELF_VALIDATION_ADDRESS).
 * address(0) hits the revert branch every time.
 *
 * Downstream impact:
 *   ExecutorLogic.validateSession (line 102) → getMainStorage().validateSession(session.id, session.validator)
 *   Any session signed with session.validator = address(0) is permanently unexecutable.
 */
contract Bug01_AddressZeroValidatorNotSkipped is Test {

    Storage public store;

    function setUp() public {
        // Storage.validateValidator and Storage.validateSession are pure view functions
        // that do NOT call getOwner() / Clones.fetchCloneArgs.
        // Deploying with `new` is sufficient; no clone setup required.
        store = new Storage();
    }

    // -----------------------------------------------------------------------
    // Demonstrate the broken path
    // -----------------------------------------------------------------------

    /// @notice NatSpec promises address(0) skips the validator check.
    ///         This test proves the promise is a lie — it reverts unconditionally.
    function test_bug01_address0_reverts_instead_of_skipping() public {
        uint256 anySessionId = 42; // not revoked — _invalidSessionId[42] == false
        address validator = address(0); // the documented "skip" sentinel

        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidValidator.selector, address(0))
        );
        store.validateSession(anySessionId, validator);
    }

    /// @notice Direct call to validateValidator also confirms address(0) is not special.
    function test_bug01_validateValidator_address0_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidValidator.selector, address(0))
        );
        store.validateValidator(address(0));
    }

    // -----------------------------------------------------------------------
    // Prove the ACTUAL sentinel is address(1), contradicting the comment
    // -----------------------------------------------------------------------

    /// @notice address(1) == SELF_VALIDATION_ADDRESS is the real bypass sentinel.
    ///         This call succeeds, proving the comment is pointing at the wrong value.
    function test_bug01_address1_is_real_sentinel_not_address0() public view {
        assertEq(
            WalletCoreLib.SELF_VALIDATION_ADDRESS,
            address(1),
            "SELF_VALIDATION_ADDRESS must be address(1)"
        );
        // Does NOT revert — address(1) is whitelisted in validateValidator
        store.validateSession(42, address(1));
    }

    // -----------------------------------------------------------------------
    // Show the end-to-end revert path that kills a signed session
    // -----------------------------------------------------------------------

    /// @notice Constructs the exact call chain that occurs in executeFromExecutor:
    ///         onlyValidSession → validateSession(session) →
    ///         getMainStorage().validateSession(session.id, session.validator)
    ///         with session.validator = address(0)
    ///
    ///         Result: session signed by a legitimate owner with validator=0x0
    ///         can never be executed — permanent DoS.
    function test_bug01_session_with_address0_validator_permanently_broken() public {
        // Simulate what ExecutorLogic.validateSession calls on Storage
        // (ExecutorLogic line 102: getMainStorage().validateSession(session.id, session.validator))
        uint256 sessionId = 1;
        address intendedNoValidatorSentinel = address(0);

        // The revert below proves that any executor holding a session
        // where session.validator == address(0) is permanently locked out.
        vm.expectRevert(
            abi.encodeWithSelector(Errors.InvalidValidator.selector, address(0))
        );
        store.validateSession(sessionId, intendedNoValidatorSentinel);
    }
}
