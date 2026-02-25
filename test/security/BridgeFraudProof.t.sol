// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/BridgeFraudProof.sol";
import "../../contracts/security/OptimisticBridgeVerifier.sol";

contract BridgeFraudProofTest is Test {
    BridgeFraudProof public fraudProof;
    OptimisticBridgeVerifier public verifier;
    address public admin = address(this);
    address public submitter = makeAddr("submitter");
    address public challenger = makeAddr("challenger");
    address public alice = makeAddr("alice");

    bytes constant PROOF = hex"123456";
    bytes32 constant STATE_COMMIT = bytes32(0);
    bytes32 constant NULLIFIER_HASH = bytes32(0);

    function setUp() public {
        verifier = new OptimisticBridgeVerifier(admin);
        fraudProof = new BridgeFraudProof(address(verifier), admin);

        // Grant RESOLVER_ROLE to fraudProof contract
        verifier.grantRole(verifier.RESOLVER_ROLE(), address(fraudProof));

        vm.deal(submitter, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(alice, 100 ether);
    }

    // ─── Helpers ───

    function _submitAndChallenge(bytes32 msgHash) internal returns (bytes32) {
        vm.prank(submitter);
        bytes32 transferId = verifier.submitTransfer{value: 1 ether}(
            msgHash,
            100 ether, // Above optimistic threshold
            PROOF,
            STATE_COMMIT,
            NULLIFIER_HASH
        );

        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.1 ether}(transferId, hex"");

        return transferId;
    }

    // ──────────────────────────────────────────────
    //  1. Core: Automated Fraud Resolution
    // ──────────────────────────────────────────────

    function test_AutomatedFraudResolution() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg"));

        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EVIDENCE"));

        OptimisticBridgeVerifier.PendingTransfer memory transfer = verifier
            .getVerification(transferId);
        assertEq(
            uint(transfer.status),
            uint(OptimisticBridgeVerifier.TransferStatus.REJECTED)
        );
    }

    // ──────────────────────────────────────────────
    //  2. Reverts: Invalid Evidence
    // ──────────────────────────────────────────────

    function test_InvalidEvidence_Reverts() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg2"));

        vm.expectRevert("Fraud not proven");
        fraudProof.submitFraudProof(transferId, PROOF, bytes("WEAK"));
    }

    // ──────────────────────────────────────────────
    //  3. Evidence length boundary
    // ──────────────────────────────────────────────

    function test_EvidenceTooShort_Reverts() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg3"));

        // Exactly 4 bytes (< 5 required)
        vm.expectRevert("Fraud not proven");
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAU"));
    }

    function test_EvidenceExactly5Bytes_FRAUDPrefix_Succeeds() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg4"));

        // Exactly 5 bytes starting with "FRAUD"
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD"));

        OptimisticBridgeVerifier.PendingTransfer memory t = verifier
            .getVerification(transferId);
        assertEq(
            uint(t.status),
            uint(OptimisticBridgeVerifier.TransferStatus.REJECTED)
        );
    }

    function test_Evidence5Bytes_NotFRAUDPrefix_Reverts() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg5"));

        // 5 bytes but doesn't start with "FRAUD"
        vm.expectRevert("Fraud not proven");
        fraudProof.submitFraudProof(transferId, PROOF, bytes("HELLO"));
    }

    // ──────────────────────────────────────────────
    //  4. Proof hash validation
    // ──────────────────────────────────────────────

    function test_ProofMismatch_Reverts() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg6"));

        // Submit fraud proof with wrong original proof
        vm.expectRevert("Original proof mismatch");
        fraudProof.submitFraudProof(
            transferId,
            hex"deadbeef", // Wrong proof
            bytes("FRAUD_EVIDENCE")
        );
    }

    // ──────────────────────────────────────────────
    //  5. Transfer must be in CHALLENGED state
    // ──────────────────────────────────────────────

    function test_NotChallenged_Reverts() public {
        // Submit but don't challenge
        vm.prank(submitter);
        bytes32 transferId = verifier.submitTransfer{value: 1 ether}(
            keccak256("msg7"),
            100 ether,
            PROOF,
            STATE_COMMIT,
            NULLIFIER_HASH
        );

        vm.expectRevert("Not challenged");
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EVIDENCE"));
    }

    // ──────────────────────────────────────────────
    //  6. Event emissions
    // ──────────────────────────────────────────────

    function test_EmitsFraudVerified() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg8"));

        vm.expectEmit(true, false, false, false);
        emit BridgeFraudProof.FraudVerified(transferId);
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));
    }

    function test_EmitsFraudProofSubmitted() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg9"));

        vm.expectEmit(true, false, false, true);
        emit BridgeFraudProof.FraudProofSubmitted(transferId, address(this));
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));
    }

    // ──────────────────────────────────────────────
    //  7. Challenger gets rewarded
    // ──────────────────────────────────────────────

    function test_ChallengerRewardedAfterFraud() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg10"));

        uint256 challengerBalBefore = challenger.balance;

        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));

        // Challenger gets their bond back + submitter's bond
        assertGt(challenger.balance, challengerBalBefore);
    }

    // ──────────────────────────────────────────────
    //  8. Double fraud proof submission
    // ──────────────────────────────────────────────

    function test_DoubleFraudProof_Reverts() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg11"));

        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));

        // Second submission — transfer is now REJECTED, not CHALLENGED
        vm.expectRevert("Not challenged");
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));
    }

    // ──────────────────────────────────────────────
    //  9. Anyone can submit fraud proof
    // ──────────────────────────────────────────────

    function test_AnyoneCanSubmitFraudProof() public {
        bytes32 transferId = _submitAndChallenge(keccak256("msg12"));

        // Alice isn't the challenger, but can submit fraud proof
        vm.prank(alice);
        fraudProof.submitFraudProof(transferId, PROOF, bytes("FRAUD_EV"));

        OptimisticBridgeVerifier.PendingTransfer memory t = verifier
            .getVerification(transferId);
        assertEq(
            uint(t.status),
            uint(OptimisticBridgeVerifier.TransferStatus.REJECTED)
        );
    }

    // ──────────────────────────────────────────────
    //  10. Immutables check
    // ──────────────────────────────────────────────

    function test_ImmutableVerifierAddress() public view {
        assertEq(address(fraudProof.optimisticVerifier()), address(verifier));
    }

    // ──────────────────────────────────────────────
    //  11. Fuzz: Evidence validation
    // ──────────────────────────────────────────────

    function testFuzz_EvidenceValidation(bytes memory evidence) public {
        bytes32 transferId = _submitAndChallenge(
            keccak256(abi.encode("msg_fuzz", evidence))
        );

        bool shouldSucceed = evidence.length >= 5 &&
            bytes5(evidence) == bytes5("FRAUD");

        if (shouldSucceed) {
            fraudProof.submitFraudProof(transferId, PROOF, evidence);
            OptimisticBridgeVerifier.PendingTransfer memory t = verifier
                .getVerification(transferId);
            assertEq(
                uint(t.status),
                uint(OptimisticBridgeVerifier.TransferStatus.REJECTED)
            );
        } else {
            vm.expectRevert("Fraud not proven");
            fraudProof.submitFraudProof(transferId, PROOF, evidence);
        }
    }
}
