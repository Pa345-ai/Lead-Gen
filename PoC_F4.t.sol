// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// PoC F4 — MEDIUM
// isValidSignature uses non-standard hash scheme inconsistent with executeWithValidator
//
// Root cause : Internal isValidSignature(address,bytes32,bytes) builds:
//                boundHash = keccak256(abi.encode(chainId, address(this), _hash))
//                digest    = keccak256("\x19\x01" || boundHash)
//              This is NOT EIP-712. executeWithValidator uses proper
//              _hashTypedDataV4 (split domainSeparator + structHash).
//              The same validator produces two different digest schemes —
//              signatures are not interchangeable between the two paths.
//
// Impact     : dApps using EIP-1271 (permit flows, order-books, bridges)
//              sign the EIP-712 digest and fail the isValidSignature validator
//              path. Signatures only work if you manually compute the
//              non-standard boundHash — which no standard library does.
//
// Run: forge test --match-contract PoC_F4 -vvvv

import "forge-std/Test.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {IValidation} from "src/interfaces/IValidation.sol";
import {IStorage}    from "src/interfaces/IStorage.sol";
import {ValidationLogic} from "src/ValidationLogic.sol";
import {WalletCore}  from "src/WalletCore.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {Call}        from "src/Types.sol";
import {Errors}      from "src/lib/Errors.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";

contract PoC_F4 is Test {
    string constant NAME    = "wallet-core";
    string constant VERSION = "1.0.0";

    bytes4 constant MAGIC_VALUE   = 0x1626ba7e;
    bytes4 constant INVALID_VALUE = 0xffffffff;

    bytes32 constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    address internal _alice;
    uint256 internal _alicePk;
    address internal _bob;

    WalletCore     internal _walletCore;
    ECDSAValidator internal _ecdsaValidator;
    DeployFactory  public   deployFactory;

    function setUp() public {
        (_alice, _alicePk) = makeAddrAndKey("alice");
        (_bob,   )         = makeAddrAndKey("bob");

        deployFactory = new DeployFactory();
        bytes32 salt  = vm.envBytes32("DEPLOY_FACTORY_SALT");

        (, address ecdsaAddr, address walletAddr) = DeployInitHelper.deployContracts(
            deployFactory, salt, NAME, VERSION
        );
        _walletCore    = WalletCore(payable(walletAddr));
        _ecdsaValidator = ECDSAValidator(ecdsaAddr);

        vm.etch(_alice, address(_walletCore).code);
        deal(_alice, 10 ether);
        vm.prank(_alice);
        IWalletCore(_alice).initialize();
    }

    function _domainSeparator() internal view returns (bytes32) {
        (,,, uint256 chainId, address verifyingContract,,) =
            WalletCore(payable(_alice)).eip712Domain();
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            chainId,
            verifyingContract
        ));
    }

    function _addValidator() internal returns (address validator) {
        bytes memory initCode = abi.encode(_alice);
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(address(_ecdsaValidator), initCode);
        validator = IValidation(_alice).computeValidatorAddress(
            address(_ecdsaValidator), initCode
        );
    }

    // ------------------------------------------------------------------
    // Test A: prove the two digest schemes are different for the same payload
    // ------------------------------------------------------------------
    function test_f4_hash_schemes_diverge() public view {
        bytes32 payload = keccak256("some dApp message");

        // What isValidSignature internally computes (non-standard):
        bytes32 boundHash     = keccak256(abi.encode(bytes32(block.chainid), _alice, payload));
        bytes32 contractDigest = keccak256(abi.encodePacked("\x19\x01", boundHash));

        // What a standard EIP-712 library would compute:
        bytes32 eip712Digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), payload)
        );

        // They differ → standard tooling can never produce a valid sig for the validator path
        assertTrue(contractDigest != eip712Digest, "F4: digests should differ");

        // Illustrate: domainSeparator ≠ boundHash (the substitution is structurally wrong)
        assertTrue(_domainSeparator() != boundHash, "F4: domainSep should differ from boundHash");

        emit log_named_bytes32("contract digest (non-standard)", contractDigest);
        emit log_named_bytes32("EIP-712 digest  (spec)        ", eip712Digest);
    }

    // ------------------------------------------------------------------
    // Test B: standard EIP-712 signature is rejected by isValidSignature
    //         validator path even though the validator is Alice's own key
    // ------------------------------------------------------------------
    function test_f4_standard_eip712_sig_rejected_by_isValidSignature() public {
        address validator = _addValidator();

        bytes32 payload = keccak256("permit: approve 1000 USDC");

        // Standard dApp computes EIP-712 digest and signs it
        bytes32 eip712Digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), payload)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, eip712Digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Present to isValidSignature with validator prefix
        bytes memory fullSig = abi.encodePacked(validator, sig);

        // Contract internally hashes with non-standard scheme → recovery fails
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(payload, fullSig);
        assertEq(result, INVALID_VALUE, "F4: standard sig should be rejected");

        console.log("[F4-B] Standard EIP-712 sig returned INVALID_VALUE");
        console.log("[F4-B] EIP-1271 integrations permanently broken for this wallet");
    }

    // ------------------------------------------------------------------
    // Test C: only a sig over the non-standard scheme passes
    //         (demonstrates the scheme mismatch explicitly)
    // ------------------------------------------------------------------
    function test_f4_only_nonstandard_scheme_passes() public {
        address validator = _addValidator();

        bytes32 payload = keccak256("permit: approve 1000 USDC");

        // Manually compute the non-standard digest the contract uses
        bytes32 boundHash      = keccak256(abi.encode(bytes32(block.chainid), _alice, payload));
        bytes32 contractDigest = keccak256(abi.encodePacked("\x19\x01", boundHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, contractDigest);
        bytes memory sig     = abi.encodePacked(r, s, v);
        bytes memory fullSig = abi.encodePacked(validator, sig);

        // Only the non-standard digest passes — no standard library computes this
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(payload, fullSig);
        assertEq(result, MAGIC_VALUE, "F4: non-standard sig should pass");

        console.log("[F4-C] Non-standard digest accepted — standard tooling cannot produce this");
    }
}
