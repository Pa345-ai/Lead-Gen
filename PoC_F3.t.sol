// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// PoC F3 — MEDIUM
// bytes32[] in _getValidationHash uses abi.encode, not abi.encodePacked
//
// Root cause : EIP-712 encodes array types as
//                keccak256(enc(el[0]) ++ enc(el[1]) ++ ...)
//              which for bytes32[] means keccak256(abi.encodePacked(arr)).
//              ValidationLogic.sol uses keccak256(abi.encode(arr)) which
//              prepends a 32-byte offset and 32-byte length — a different
//              byte string.
//
// Impact     : Every off-chain EIP-712 library (ethers.js, viem, …)
//              produces a digest that never matches what the contract
//              verifies → executeWithValidator is permanently broken for
//              all spec-compliant relayers/signers.
//
// Run: forge test --match-contract PoC_F3 -vvvv

import "forge-std/Test.sol";
import {IWalletCore}    from "src/interfaces/IWalletCore.sol";
import {IValidation}    from "src/interfaces/IValidation.sol";
import {IStorage}       from "src/interfaces/IStorage.sol";
import {ValidationLogic} from "src/ValidationLogic.sol";
import {WalletCore}     from "src/WalletCore.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {Call, Session}  from "src/Types.sol";
import {Errors}         from "src/lib/Errors.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";

contract PoC_F3 is Test {
    string constant NAME    = "wallet-core";
    string constant VERSION = "1.0.0";

    bytes32 constant CALLS_TYPEHASH =
        keccak256("Calls(address wallet,uint256 nonce,bytes32[] calls)");
    bytes32 constant CALL_TYPEHASH =
        keccak256("Call(address target,uint256 value,bytes data)");
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

    // ------------------------------------------------------------------
    // Helper: compute domain separator from wallet's eip712Domain()
    // ------------------------------------------------------------------
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

    // ------------------------------------------------------------------
    // Helper: build the spec-compliant struct hash for a given nonce+calls
    // Extracted to avoid stack-too-deep in the test function.
    // ------------------------------------------------------------------
    function _specStructHash(
        uint256 nonce,
        Call[] memory calls
    ) internal view returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i; i < calls.length; i++) {
            callHashes[i] = keccak256(abi.encode(
                CALL_TYPEHASH,
                calls[i].target,
                calls[i].value,
                keccak256(calls[i].data)
            ));
        }
        return keccak256(abi.encode(
            CALLS_TYPEHASH,
            WalletCore(payable(_alice)).ADDRESS_THIS(),
            nonce,
            keccak256(abi.encodePacked(callHashes))  // ← EIP-712 spec
        ));
    }

    // ------------------------------------------------------------------
    // Test A: structural proof — abi.encode vs encodePacked differ for bytes32[]
    // ------------------------------------------------------------------
    function test_f3_encoding_produces_different_hashes() public {
        bytes32[] memory arr = new bytes32[](1);
        arr[0] = keccak256("payload");

        bytes32 contractHash = keccak256(abi.encode(arr));       // what contract does
        bytes32 specHash     = keccak256(abi.encodePacked(arr)); // what EIP-712 requires

        assertTrue(contractHash != specHash, "F3: hashes should differ");

        // Layout difference:
        // abi.encode(bytes32[1])      → 96 bytes: [offset=0x20][length=1][el0]
        // abi.encodePacked(bytes32[1]) → 32 bytes: [el0]
        assertEq(abi.encode(arr).length,       96, "F3: abi.encode length wrong");
        assertEq(abi.encodePacked(arr).length, 32, "F3: encodePacked length wrong");

        emit log_named_bytes32("contract (abi.encode)   ", contractHash);
        emit log_named_bytes32("spec     (encodePacked) ", specHash);
    }

    // ------------------------------------------------------------------
    // Test B: spec-compliant relayer signature is always rejected
    // Note: stack-too-deep fixed by extracting _specStructHash helper
    // ------------------------------------------------------------------
    function test_f3_relayer_signature_always_rejected() public {
        // Add ECDSA validator for Alice
        bytes memory initCode = abi.encode(_alice);
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(address(_ecdsaValidator), initCode);
        address validator = IValidation(_alice).computeValidatorAddress(
            address(_ecdsaValidator), initCode
        );

        // Build call
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _bob, value: 0.1 ether, data: ""});

        uint256 nonce = IStorage(WalletCore(payable(_alice)).getMainStorage()).getNonce();

        // Contract's digest (uses abi.encode — buggy)
        bytes32 contractDigest = ValidationLogic(_alice).getValidationTypedHash(nonce, calls);

        // Spec-compliant digest (uses encodePacked — correct)
        bytes32 specDigest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), _specStructHash(nonce, calls))
        );

        // Must diverge — this is the bug
        assertTrue(contractDigest != specDigest, "F3: digests should differ");

        // Relayer signs the spec-correct digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, specDigest);
        bytes memory sig = abi.encodePacked(validator, abi.encodePacked(r, s, v));

        // Contract rejects it — signature recovery yields wrong address
        vm.expectRevert(Errors.InvalidSignature.selector);
        IWalletCore(_alice).executeWithValidator(calls, validator, sig);

        console.log("[F3] contractDigest != specDigest: confirmed");
        console.log("[F3] executeWithValidator reverted with InvalidSignature");
        console.log("[F3] All spec-compliant relayers permanently broken");
    }
}
