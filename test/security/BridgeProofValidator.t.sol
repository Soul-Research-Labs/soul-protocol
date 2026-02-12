// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BridgeProofValidator} from "../../contracts/security/BridgeProofValidator.sol";

contract BridgeProofValidatorTest is Test {
    BridgeProofValidator public validator;

    address public admin;
    address public operator;
    address public guardian;
    address public challenger;
    address public watchtower1;
    address public watchtower2;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 constant WATCHTOWER_ROLE = keccak256("WATCHTOWER_ROLE");

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        guardian = makeAddr("guardian");
        challenger = makeAddr("challenger");
        watchtower1 = makeAddr("watchtower1");
        watchtower2 = makeAddr("watchtower2");

        validator = new BridgeProofValidator(admin);
        validator.grantRole(OPERATOR_ROLE, operator);
        validator.grantRole(GUARDIAN_ROLE, guardian);
        validator.grantRole(CHALLENGER_ROLE, challenger);

        validator.addWatchtower(watchtower1);
    }

    // ──────── Helpers ────────

    function _submitProof(bytes32 proofHash, uint256 value) internal {
        vm.prank(operator);
        validator.submitProof(
            proofHash,
            keccak256("content"),
            value,
            keccak256("ETH")
        );
    }

    function _confirmAndFinalize(bytes32 proofHash) internal {
        // Watchtower confirm
        vm.prank(watchtower1);
        validator.confirmProof(proofHash);

        // Wait past challenge period
        vm.warp(block.timestamp + 4 hours + 1);
        validator.finalizeProof(proofHash);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsDefaults() public view {
        assertEq(validator.maxProofBlocks(), 300);
        assertEq(validator.challengePeriod(), 4 hours);
        assertEq(validator.currentEpoch(), 1);
        assertTrue(validator.watchtowers(admin));
        assertEq(validator.watchtowerCount(), 2); // admin + watchtower1
        assertEq(validator.requiredWatchtowerConfirmations(), 1);
    }

    function test_Constructor_SetsWithdrawalCaps() public view {
        (
            uint256 perTx,
            uint256 perEpoch,
            uint256 duration,
            bool enabled
        ) = validator.withdrawalCaps();
        assertEq(perTx, 100 ether);
        assertEq(perEpoch, 1000 ether);
        assertEq(duration, 24 hours);
        assertTrue(enabled);
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function test_SubmitProof() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        (
            bytes32 proofHash,
            bytes32 contentHash,
            address submitter,
            uint256 submittedAt, // submittedBlock // expiresAt // expiresBlock // challengeDeadline
            ,
            ,
            ,
            ,
            BridgeProofValidator.ProofStatus status,
            uint256 value,

        ) = // sourceChain
            validator.proofRecords(hash);

        assertEq(proofHash, hash);
        assertEq(contentHash, keccak256("content"));
        assertEq(submitter, operator);
        assertGt(submittedAt, 0);
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.SUBMITTED)
        );
        assertEq(value, 1 ether);
    }

    function test_SubmitProof_EventEmitted() public {
        bytes32 hash = keccak256("proof1");
        vm.prank(operator);
        vm.expectEmit(true, true, false, true);
        emit BridgeProofValidator.ProofSubmitted(
            hash,
            operator,
            1 ether,
            block.number + 300,
            block.timestamp + 4 hours
        );
        validator.submitProof(hash, keccak256("c"), 1 ether, keccak256("ETH"));
    }

    function test_SubmitProof_RevertDuplicate() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(operator);
        vm.expectRevert(BridgeProofValidator.ProofAlreadyExists.selector);
        validator.submitProof(hash, keccak256("c"), 1 ether, keccak256("ETH"));
    }

    function test_SubmitProof_RevertNotOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        validator.submitProof(
            keccak256("p"),
            keccak256("c"),
            1 ether,
            keccak256("ETH")
        );
    }

    function test_SubmitProof_RevertExceedsPerTxCap() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeProofValidator.ExceedsWithdrawalCap.selector,
                200 ether,
                100 ether
            )
        );
        validator.submitProof(
            keccak256("p"),
            keccak256("c"),
            200 ether,
            keccak256("ETH")
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WATCHTOWER CONFIRM
    //////////////////////////////////////////////////////////////*/

    function test_ConfirmProof() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(watchtower1);
        validator.confirmProof(hash);

        assertEq(validator.watchtowerConfirmationCount(hash), 1);
    }

    function test_ConfirmProof_RevertNotWatchtower() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(address(0xDEAD));
        vm.expectRevert(BridgeProofValidator.NotWatchtower.selector);
        validator.confirmProof(hash);
    }

    function test_ConfirmProof_RevertAlreadyConfirmed() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(watchtower1);
        validator.confirmProof(hash);

        vm.prank(watchtower1);
        vm.expectRevert(BridgeProofValidator.AlreadyConfirmed.selector);
        validator.confirmProof(hash);
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF FINALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_FinalizeProof() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        _confirmAndFinalize(hash);

        BridgeProofValidator.ProofStatus status = validator.getProofStatus(
            hash
        );
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.FINALIZED)
        );
        assertTrue(validator.isProofValid(hash));
    }

    function test_FinalizeProof_RevertChallengePeriodActive() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(watchtower1);
        validator.confirmProof(hash);

        // Try finalize before challenge period ends
        vm.expectRevert(BridgeProofValidator.ChallengePeriodActive.selector);
        validator.finalizeProof(hash);
    }

    function test_FinalizeProof_RevertInsufficientConfirmations() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        // Set required to 2
        validator.setRequiredConfirmations(2);

        vm.prank(watchtower1);
        validator.confirmProof(hash);

        vm.warp(block.timestamp + 4 hours + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeProofValidator.InsufficientConfirmations.selector,
                1,
                2
            )
        );
        validator.finalizeProof(hash);
    }

    function test_FinalizeProof_Idempotent() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);
        _confirmAndFinalize(hash);

        // Second finalize should not revert (idempotent)
        validator.finalizeProof(hash);
    }

    function test_ProofExpiry() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        // Roll past expiry (300 blocks)
        vm.roll(block.number + 301);

        BridgeProofValidator.ProofStatus status = validator.getProofStatus(
            hash
        );
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.EXPIRED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CHALLENGES
    //////////////////////////////////////////////////////////////*/

    function test_ChallengeProof() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(challenger);
        validator.challengeProof(hash, hex"deadbeef");

        BridgeProofValidator.ProofStatus status = validator.getProofStatus(
            hash
        );
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.CHALLENGED)
        );
        assertEq(validator.totalChallenges(), 1);
    }

    function test_ChallengeProof_RevertAfterDeadline() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.warp(block.timestamp + 4 hours + 1);

        vm.prank(challenger);
        vm.expectRevert(BridgeProofValidator.ChallengePeriodEnded.selector);
        validator.challengeProof(hash, hex"deadbeef");
    }

    function test_ResolveChallenge_Upheld() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(challenger);
        validator.challengeProof(hash, hex"deadbeef");

        vm.prank(guardian);
        validator.resolveChallenge(hash, 0, true);

        BridgeProofValidator.ProofStatus status = validator.getProofStatus(
            hash
        );
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.REJECTED)
        );
        assertEq(validator.successfulChallenges(), 1);
    }

    function test_ResolveChallenge_NotUpheld() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(challenger);
        validator.challengeProof(hash, hex"deadbeef");

        vm.prank(guardian);
        validator.resolveChallenge(hash, 0, false);

        // Back to SUBMITTED after all challenges resolved
        BridgeProofValidator.ProofStatus status = validator.getProofStatus(
            hash
        );
        assertEq(
            uint8(status),
            uint8(BridgeProofValidator.ProofStatus.SUBMITTED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       WATCHTOWER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_AddWatchtower() public {
        validator.addWatchtower(watchtower2);
        assertTrue(validator.watchtowers(watchtower2));
        assertEq(validator.watchtowerCount(), 3);
    }

    function test_AddWatchtower_RevertAlreadyExists() public {
        vm.expectRevert(BridgeProofValidator.AlreadyWatchtower.selector);
        validator.addWatchtower(watchtower1);
    }

    function test_RemoveWatchtower() public {
        validator.addWatchtower(watchtower2);

        validator.removeWatchtower(watchtower2);
        assertFalse(validator.watchtowers(watchtower2));
    }

    function test_RemoveWatchtower_RevertLastOne() public {
        // Remove watchtower1, leaving only admin
        validator.removeWatchtower(watchtower1);

        // Try removing admin (last one)
        vm.expectRevert(
            BridgeProofValidator.CannotRemoveLastWatchtower.selector
        );
        validator.removeWatchtower(admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_SetMaxProofBlocks() public {
        validator.setMaxProofBlocks(500);
        assertEq(validator.maxProofBlocks(), 500);
    }

    function test_SetMaxProofBlocks_RevertInvalid() public {
        vm.expectRevert(BridgeProofValidator.InvalidBlocks.selector);
        validator.setMaxProofBlocks(0);

        vm.expectRevert(BridgeProofValidator.InvalidBlocks.selector);
        validator.setMaxProofBlocks(10000); // > MAX_PROOF_BLOCKS
    }

    function test_SetChallengePeriod() public {
        validator.setChallengePeriod(2 hours);
        assertEq(validator.challengePeriod(), 2 hours);
    }

    function test_SetChallengePeriod_RevertTooShort() public {
        vm.expectRevert(BridgeProofValidator.PeriodTooShort.selector);
        validator.setChallengePeriod(30 minutes);
    }

    function test_SetWithdrawalCaps() public {
        validator.setWithdrawalCaps(50 ether, 500 ether, 12 hours, true);

        (
            uint256 perTx,
            uint256 perEpoch,
            uint256 duration,
            bool enabled
        ) = validator.withdrawalCaps();
        assertEq(perTx, 50 ether);
        assertEq(perEpoch, 500 ether);
        assertEq(duration, 12 hours);
        assertTrue(enabled);
    }

    function test_SetWithdrawalCaps_RevertInvalid() public {
        vm.expectRevert(BridgeProofValidator.InvalidCapConfiguration.selector);
        validator.setWithdrawalCaps(200 ether, 100 ether, 12 hours, true);

        vm.expectRevert(BridgeProofValidator.EpochTooShort.selector);
        validator.setWithdrawalCaps(50 ether, 500 ether, 30 minutes, true);
    }

    function test_SetRequiredConfirmations() public {
        validator.addWatchtower(watchtower2);
        validator.setRequiredConfirmations(2);
        assertEq(validator.requiredWatchtowerConfirmations(), 2);
    }

    function test_SetRequiredConfirmations_RevertInvalid() public {
        vm.expectRevert(BridgeProofValidator.InvalidCount.selector);
        validator.setRequiredConfirmations(0);

        vm.expectRevert(BridgeProofValidator.InvalidCount.selector);
        validator.setRequiredConfirmations(100); // > watchtowerCount
    }

    function test_Pause_Unpause() public {
        vm.prank(guardian);
        validator.pause();

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        validator.submitProof(
            keccak256("p"),
            keccak256("c"),
            1 ether,
            keccak256("ETH")
        );

        validator.unpause();

        vm.prank(operator);
        validator.submitProof(
            keccak256("p"),
            keccak256("c"),
            1 ether,
            keccak256("ETH")
        );
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetProofStatus_None() public view {
        assertEq(
            uint8(validator.getProofStatus(keccak256("nonexistent"))),
            uint8(BridgeProofValidator.ProofStatus.NONE)
        );
    }

    function test_IsProofValid_False_NotFinalized() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);
        assertFalse(validator.isProofValid(hash));
    }

    function test_GetRemainingEpochCapacity() public view {
        assertEq(validator.getRemainingEpochCapacity(), 1000 ether);
    }

    function test_GetChallengeCount() public {
        bytes32 hash = keccak256("proof1");
        _submitProof(hash, 1 ether);

        vm.prank(challenger);
        validator.challengeProof(hash, hex"deadbeef");

        assertEq(validator.getChallengeCount(hash), 1);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SubmitAndConfirm(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));

        vm.prank(operator);
        validator.submitProof(
            proofHash,
            keccak256("c"),
            1 ether,
            keccak256("ETH")
        );

        vm.prank(watchtower1);
        validator.confirmProof(proofHash);

        assertEq(validator.watchtowerConfirmationCount(proofHash), 1);
        assertEq(validator.totalProofs(), 1);
    }

    function testFuzz_SubmitValueCapped(uint256 value) public {
        value = bound(value, 0, 100 ether);

        vm.prank(operator);
        validator.submitProof(
            keccak256(abi.encode(value)),
            keccak256("c"),
            value,
            keccak256("ETH")
        );
        assertEq(validator.totalProofs(), 1);
    }
}
