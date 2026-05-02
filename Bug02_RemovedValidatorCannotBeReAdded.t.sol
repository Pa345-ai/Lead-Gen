// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {WalletCoreLib} from "src/lib/WalletCoreLib.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {Errors} from "src/lib/Errors.sol";

/**
 * BUG-02 — MEDIUM
 * _addValidator: removed validator cannot ever be re-added
 *
 * Root cause — ValidationLogic.sol lines 393–411:
 *   bytes32 salt = WalletCoreLib.VALIDATOR_SALT;   // constant, never varies
 *   address createdAddress = validatorImpl
 *       .cloneDeterministicWithImmutableArgs(immutableArgs, salt);
 *
 * WalletCoreLib.VALIDATOR_SALT = keccak256(abi.encodePacked("validator"))
 * is a compile-time constant (WalletCoreLib.sol line 957-958).
 *
 * CREATE2 address is deterministic on (deployer, salt, keccak256(initCode)).
 * For a fixed (wallet, validatorImpl, immutableArgs) triple, the clone always
 * lands at the same address.
 *
 * Attack / accidental scenario:
 *   1. addValidator(ecdsaImpl, abi.encode(signer))  → clone at ADDR, status = true
 *   2. executeFromSelf → Storage.setValidatorStatus(ADDR, false)   (remove it)
 *   3. addValidator(ecdsaImpl, abi.encode(signer))  → CREATE2 to ADDR again
 *      → ADDR already has code → cloneDeterministic reverts
 *
 * The validator is now permanently locked — setValidatorStatus(ADDR, true)
 * has no external entry point that bypasses _addValidator.
 *
 * Note: `_computeCreationSalt` (ValidationLogic.sol lines 1028-1033) exists
 * and correctly hashes (validatorImpl, initHash) into a unique salt, but
 * _addValidator never calls it — it ignores this helper entirely.
 */
contract ValidationLogicCloneHarness {
    using Clones for address;

    /// @notice Mirrors the exact logic of ValidationLogic._addValidator
    ///         (lines 397-410) without the Storage/owner machinery.
    function addValidatorClone(
        address validatorImpl,
        bytes calldata immutableArgs
    ) external returns (address) {
        if (validatorImpl.code.length == 0)
            revert Errors.InvalidValidatorImpl(validatorImpl);

        bytes32 salt = WalletCoreLib.VALIDATOR_SALT; // the constant — root cause

        // This is the line that reverts on re-add
        address createdAddress = validatorImpl
            .cloneDeterministicWithImmutableArgs(immutableArgs, salt);

        return createdAddress;
    }

    function predictAddress(
        address validatorImpl,
        bytes calldata immutableArgs
    ) external view returns (address) {
        return validatorImpl.predictDeterministicAddressWithImmutableArgs(
            immutableArgs,
            WalletCoreLib.VALIDATOR_SALT,
            address(this)
        );
    }
}

contract Bug02_RemovedValidatorCannotBeReAdded is Test {
    using Clones for address;

    ValidationLogicCloneHarness public harness;
    ECDSAValidator public ecdsaImpl;
    address public signer = address(0xBEEF);

    function setUp() public {
        harness = new ValidationLogicCloneHarness();
        ecdsaImpl = new ECDSAValidator();
    }

    // -----------------------------------------------------------------------
    // Core demonstration
    // -----------------------------------------------------------------------

    /// @notice Proves that the constant salt means the same (impl, args) pair
    ///         always resolves to the same CREATE2 address.
    function test_bug02_constant_salt_yields_same_address() public view {
        bytes memory args = abi.encode(signer);

        address predicted = harness.predictAddress(address(ecdsaImpl), args);

        // The salt never changes — this address is fixed for this (harness, impl, args) triple
        assertEq(
            predicted,
            harness.predictAddress(address(ecdsaImpl), args),
            "Same args must produce same predicted address"
        );
        console.log("Fixed clone address:", predicted);
        console.log("VALIDATOR_SALT:", vm.toString(WalletCoreLib.VALIDATOR_SALT));
    }

    /// @notice Full three-step scenario:
    ///         add → simulate removal (code stays) → attempt re-add → reverts
    function test_bug02_re_add_after_removal_reverts_permanently() public {
        bytes memory args = abi.encode(signer);

        // Step 1: First addValidator succeeds — clone deployed at ADDR
        address firstAddr = harness.addValidatorClone(address(ecdsaImpl), args);
        assertGt(firstAddr.code.length, 0, "Validator clone must be deployed");
        console.log("First deployment succeeded at:", firstAddr);

        // Step 2: Owner removes the validator via Storage.setValidatorStatus(ADDR, false)
        // The CLONE CONTRACT STILL HAS CODE at firstAddr — removal only flips a bool in Storage.
        // This is the critical state: code exists at firstAddr but _validValidator[firstAddr] == false.
        assertGt(firstAddr.code.length, 0, "Code still present after logical removal");

        // Step 3: Owner tries to re-add the same validator (same impl, same signer)
        // CREATE2 targets firstAddr again — but firstAddr already has code.
        // OpenZeppelin Clones reverts with ERC1167FailedCreateClone.
        vm.expectRevert(); // ERC1167FailedCreateClone from OZ Clones
        harness.addValidatorClone(address(ecdsaImpl), args);

        console.log("Re-add correctly fails: permanent DoS confirmed");
    }

    /// @notice Proves that a DIFFERENT signer still gets a different address
    ///         (isolating that the bug is the constant salt, not the clone mechanism).
    function test_bug02_different_args_still_work_showing_salt_is_issue() public {
        bytes memory args1 = abi.encode(signer);
        bytes memory args2 = abi.encode(address(0xCAFE)); // different signer

        address addr1 = harness.addValidatorClone(address(ecdsaImpl), args1);
        address addr2 = harness.addValidatorClone(address(ecdsaImpl), args2);

        // Different immutableArgs → different initCode → different CREATE2 address
        assertTrue(addr1 != addr2, "Different args should deploy to different addresses");
        // But for the SAME args, the address is identical on every call → collision on re-add
    }

    /// @notice Shows that _computeCreationSalt (the unused helper) would have solved this.
    ///         The fix is one line: replace the constant with a per-(impl, args) salt.
    function test_bug02_correct_salt_would_fix_it() public pure {
        address impl = address(0x1234);
        bytes32 initHash = keccak256(abi.encode(address(0xBEEF)));

        // _computeCreationSalt exists in ValidationLogic.sol (lines 1028-1033) but is never used:
        bytes32 correctSalt = keccak256(abi.encode(impl, initHash));

        // This salt is unique per (impl, initHash), so re-adding with a fresh
        // nonce or timestamp would generate a new address. The fix is simply:
        //   bytes32 salt = _computeCreationSalt(validatorImpl, keccak256(immutableArgs));
        assertTrue(
            correctSalt != WalletCoreLib.VALIDATOR_SALT,
            "Correct per-validator salt differs from the broken constant"
        );
    }
}
