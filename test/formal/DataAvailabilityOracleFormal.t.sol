// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/privacy/DataAvailabilityOracle.sol";

/**
 * @title DataAvailabilityOracle Formal Property Tests
 * @notice Fuzz-based invariant checks for attestor stake lifecycle,
 *         challenge bond accounting, and commitment status transitions
 */
contract DataAvailabilityOracleFormalTest is Test {
    DataAvailabilityOracle public dao;

    bytes32 public constant DA_ADMIN_ROLE = keccak256("DA_ADMIN_ROLE");
    bytes32 public constant ATTESTOR_ROLE = keccak256("ATTESTOR_ROLE");

    function setUp() public {
        dao = new DataAvailabilityOracle(address(this));
    }

    receive() external payable {}

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    /**
     * @notice Property: Attestor registration requires at least MIN_ATTESTOR_STAKE
     * @dev Fuzz random stake amounts — registration below minimum must revert
     */
    function test_AttestorRegistrationRequiresMinStake(
        uint256 stakeAmount
    ) public {
        stakeAmount = bound(stakeAmount, 0, 10 ether);
        address attestor = address(0xA1);

        vm.deal(attestor, stakeAmount);
        vm.prank(attestor);

        if (stakeAmount < dao.MIN_ATTESTOR_STAKE()) {
            vm.expectRevert();
            dao.registerAttestor{value: stakeAmount}();
        } else {
            uint256 countBefore = dao.totalAttestors();
            dao.registerAttestor{value: stakeAmount}();
            uint256 countAfter = dao.totalAttestors();
            assertEq(countAfter, countBefore + 1, "Attestor count must increment by 1");
        }
    }

    /**
     * @notice Property: Challenge bond must meet MIN_CHALLENGER_BOND
     * @dev Fuzz random bond amounts — challenges below minimum must revert
     */
    function test_ChallengeBondMinimum(uint256 bondAmount) public {
        bondAmount = bound(bondAmount, 0, 2 ether);

        // First, create a commitment to challenge
        bytes32 payloadHash = keccak256("test-payload");
        bytes32 erasureRoot = keccak256("erasure-root");
        bytes32 commitmentId = dao.submitDACommitment(
            payloadHash,
            erasureRoot,
            1024,
            "ipfs://test",
            3600
        );

        address challenger = address(0xC1);
        vm.deal(challenger, bondAmount);
        vm.prank(challenger);

        if (bondAmount < dao.MIN_CHALLENGER_BOND()) {
            vm.expectRevert();
            dao.challengeAvailability{value: bondAmount}(commitmentId);
        } else {
            uint256 challengesBefore = dao.totalChallenges();
            dao.challengeAvailability{value: bondAmount}(commitmentId);
            uint256 challengesAfter = dao.totalChallenges();
            assertEq(challengesAfter, challengesBefore + 1, "Challenge count must increment");
        }
    }

    /**
     * @notice Property: Commitment counter is monotonically increasing
     * @dev Submit multiple commitments, verify counter only goes up
     */
    function test_CommitmentCounterMonotonicity(uint8 numCommitments) public {
        numCommitments = uint8(bound(numCommitments, 1, 10));

        uint256 prevCount = dao.totalCommitments();

        for (uint8 i = 0; i < numCommitments; i++) {
            bytes32 payload = keccak256(abi.encodePacked("payload", i));

            dao.submitDACommitment(
                payload,
                keccak256(abi.encodePacked("erasure", i)),
                uint256(i + 1) * 1024,
                string(abi.encodePacked("ipfs://", i)),
                3600
            );

            uint256 newCount = dao.totalCommitments();
            assertGt(newCount, prevCount, "Commitment counter must monotonically increase");
            prevCount = newCount;
        }
    }

    /**
     * @notice Property: Double attestation prevention
     * @dev Same attestor cannot attest the same commitment twice
     */
    function test_DoubleAttestationPrevention() public {
        // Register an attestor
        address attestor = address(0xA2);
        vm.deal(attestor, 1 ether);
        vm.prank(attestor);
        dao.registerAttestor{value: 1 ether}();

        // Create a commitment
        bytes32 commitmentId = dao.submitDACommitment(
            keccak256("payload"),
            keccak256("erasure"),
            1024,
            "ipfs://test",
            3600
        );

        // First attestation should succeed
        vm.prank(attestor);
        dao.attestAvailability(commitmentId);

        assertTrue(dao.attestations(commitmentId, attestor), "Attestation should be recorded");

        // Second attestation should revert
        vm.prank(attestor);
        vm.expectRevert();
        dao.attestAvailability(commitmentId);
    }

    /**
     * @notice Property: Attestor exit returns stake
     * @dev Register then exit, verify balance is returned correctly
     */
    function test_AttestorExitReturnsStake(uint256 stakeAmount) public {
        stakeAmount = bound(stakeAmount, dao.MIN_ATTESTOR_STAKE(), 5 ether);

        address attestor = address(0xA3);
        vm.deal(attestor, stakeAmount);

        vm.prank(attestor);
        dao.registerAttestor{value: stakeAmount}();

        uint256 balanceBefore = attestor.balance;

        vm.prank(attestor);
        dao.exitAttestor();

        uint256 balanceAfter = attestor.balance;

        assertEq(balanceAfter, balanceBefore + stakeAmount,
            "Attestor must receive full stake back on exit");
    }
}
