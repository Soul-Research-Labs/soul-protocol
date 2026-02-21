// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/BridgeWatchtower.sol";

contract BridgeWatchtowerTest is Test {
    BridgeWatchtower public watchtower;
    address public admin = address(0xA);
    address public wt1 = address(0x1);
    address public wt2 = address(0x2);
    address public wt3 = address(0x3);
    address public wt4 = address(0x4);
    address public wt5 = address(0x5);
    address public outsider = address(0xBAD);

    function setUp() public {
        watchtower = new BridgeWatchtower(admin);
        // Fund watchtowers
        vm.deal(wt1, 10 ether);
        vm.deal(wt2, 10 ether);
        vm.deal(wt3, 10 ether);
        vm.deal(wt4, 10 ether);
        vm.deal(wt5, 10 ether);
        vm.deal(outsider, 10 ether);
    }

    // ============= Registration =============

    function test_Register() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(info.operator, wt1);
        assertEq(info.stake, 1 ether);
        assertEq(
            uint8(info.status),
            uint8(BridgeWatchtower.WatchtowerStatus.ACTIVE)
        );
    }

    function test_Register_EmitsEvent() public {
        vm.prank(wt1);
        vm.expectEmit(true, false, false, true);
        emit BridgeWatchtower.WatchtowerRegistered(wt1, 2 ether);
        watchtower.register{value: 2 ether}();
    }

    function test_Register_RevertInsufficientStake() public {
        vm.prank(wt1);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeWatchtower.InsufficientStake.selector,
                0.5 ether,
                1 ether
            )
        );
        watchtower.register{value: 0.5 ether}();
    }

    function test_Register_RevertAlreadyRegistered() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.AlreadyRegistered.selector);
        watchtower.register{value: 1 ether}();
    }

    function test_Register_IncrementsActiveCount() public {
        _registerWatchtowers(3);
        assertEq(watchtower.getActiveWatchtowerCount(), 3);
    }

    function test_Register_UpdatesTotalStaked() public {
        vm.prank(wt1);
        watchtower.register{value: 2 ether}();
        vm.prank(wt2);
        watchtower.register{value: 3 ether}();
        assertEq(watchtower.totalStaked(), 5 ether);
    }

    // ============= AddStake =============

    function test_AddStake() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        watchtower.addStake{value: 2 ether}();
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(info.stake, 3 ether);
    }

    function test_AddStake_RevertNotRegistered() public {
        vm.prank(outsider);
        vm.expectRevert(BridgeWatchtower.NotRegistered.selector);
        watchtower.addStake{value: 1 ether}();
    }

    // ============= Exit Flow =============

    function test_RequestExit() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        watchtower.requestExit();
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(
            uint8(info.status),
            uint8(BridgeWatchtower.WatchtowerStatus.EXITING)
        );
    }

    function test_RequestExit_RevertNotRegistered() public {
        vm.prank(outsider);
        vm.expectRevert(BridgeWatchtower.NotRegistered.selector);
        watchtower.requestExit();
    }

    function test_CompleteExit() public {
        vm.prank(wt1);
        watchtower.register{value: 2 ether}();
        vm.prank(wt1);
        watchtower.requestExit();
        vm.warp(block.timestamp + 14 days + 1);
        uint256 balBefore = wt1.balance;
        vm.prank(wt1);
        watchtower.completeExit();
        assertEq(wt1.balance, balBefore + 2 ether);
        assertEq(watchtower.getActiveWatchtowerCount(), 0);
    }

    function test_CompleteExit_RevertBeforeDelay() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        watchtower.requestExit();
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.ExitDelayNotPassed.selector);
        watchtower.completeExit();
    }

    function test_CompleteExit_RevertNotExiting() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.ExitNotRequested.selector);
        watchtower.completeExit();
    }

    // ============= Reporting =============

    function test_SubmitReport() public {
        _registerWatchtowers(1);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.INVALID_PROOF,
            keccak256("suspicious"),
            hex"dead"
        );
        assertTrue(reportId != bytes32(0));
        BridgeWatchtower.AnomalyReport memory report = watchtower.getReport(
            reportId
        );
        assertEq(report.reporter, wt1);
        assertEq(report.confirmations, 1); // auto-confirmed by reporter
        assertEq(
            uint8(report.status),
            uint8(BridgeWatchtower.ReportStatus.PENDING)
        );
    }

    function test_SubmitReport_RevertNotWatchtower() public {
        vm.prank(outsider);
        vm.expectRevert();
        watchtower.submitReport(
            BridgeWatchtower.ReportType.INVALID_PROOF,
            keccak256("suspicious"),
            hex"dead"
        );
    }

    function test_SubmitReport_IncrementsReportCount() public {
        _registerWatchtowers(1);
        vm.prank(wt1);
        watchtower.submitReport(
            BridgeWatchtower.ReportType.STATE_MISMATCH,
            bytes32(uint256(1)),
            hex"01"
        );
        vm.prank(wt1);
        watchtower.submitReport(
            BridgeWatchtower.ReportType.DOUBLE_SPEND,
            bytes32(uint256(2)),
            hex"02"
        );
        assertEq(watchtower.reportCount(), 2);
    }

    // ============= Voting =============

    function test_VoteOnReport_Confirm() public {
        _registerWatchtowers(3);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.INVALID_PROOF,
            keccak256("target"),
            hex"beef"
        );
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, true);
        BridgeWatchtower.AnomalyReport memory report = watchtower.getReport(
            reportId
        );
        assertEq(report.confirmations, 2);
    }

    function test_VoteOnReport_Reject() public {
        _registerWatchtowers(3);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.BRIDGE_DELAY,
            keccak256("target"),
            hex"cafe"
        );
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, false);
        BridgeWatchtower.AnomalyReport memory report = watchtower.getReport(
            reportId
        );
        assertEq(report.rejections, 1);
    }

    function test_VoteOnReport_RevertAlreadyVoted() public {
        // Use 5 watchtowers so threshold=3, reporter auto-confirms (1), wt2 reject (1 of each)
        // Report stays PENDING, so re-vote from wt2 hits AlreadyVoted
        _registerWatchtowers(5);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.INVALID_PROOF,
            keccak256("x"),
            hex"aa"
        );
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, false); // reject so neither side hits threshold
        vm.prank(wt2);
        vm.expectRevert(BridgeWatchtower.AlreadyVoted.selector);
        watchtower.voteOnReport(reportId, true);
    }

    function test_VoteOnReport_RevertNotFound() public {
        _registerWatchtowers(1);
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.ReportNotFound.selector);
        watchtower.voteOnReport(bytes32(uint256(999)), true);
    }

    function test_ReportFinalization_Confirmed() public {
        // With 4 watchtowers, ceiling threshold = (4 * 6666 + 9999) / 10000 = 3
        // Reporter auto-confirms (1), need 2 more votes to reach threshold of 3
        _registerWatchtowers(4);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.INVALID_PROOF,
            keccak256("bad_proof"),
            hex"dead"
        );
        // wt1 auto-confirmed (1), wt2 confirms (2), wt3 confirms (3) = threshold met
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, true);
        vm.prank(wt3);
        watchtower.voteOnReport(reportId, true);
        BridgeWatchtower.AnomalyReport memory report = watchtower.getReport(
            reportId
        );
        assertEq(
            uint8(report.status),
            uint8(BridgeWatchtower.ReportStatus.CONFIRMED)
        );
    }

    function test_ReportFinalization_Rejected() public {
        _registerWatchtowers(4);
        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.SUSPICIOUS_PATTERN,
            keccak256("maybe_bad"),
            hex"0001"
        );
        // Need 3 rejections (ceiling threshold for 4 watchtowers)
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, false);
        vm.prank(wt3);
        watchtower.voteOnReport(reportId, false);
        vm.prank(wt4);
        watchtower.voteOnReport(reportId, false);
        BridgeWatchtower.AnomalyReport memory report = watchtower.getReport(
            reportId
        );
        assertEq(
            uint8(report.status),
            uint8(BridgeWatchtower.ReportStatus.REJECTED)
        );
    }

    function test_FalseReportSlashes() public {
        _registerWatchtowers(4);
        BridgeWatchtower.Watchtower memory infoBefore = watchtower
            .getWatchtowerInfo(wt1);
        uint256 stakeBefore = infoBefore.stake;

        vm.prank(wt1);
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.STATE_MISMATCH,
            keccak256("false_alarm"),
            hex"0002"
        );
        // Reject it — need 3 rejections (ceiling threshold for 4 watchtowers)
        vm.prank(wt2);
        watchtower.voteOnReport(reportId, false);
        vm.prank(wt3);
        watchtower.voteOnReport(reportId, false);
        vm.prank(wt4);
        watchtower.voteOnReport(reportId, false);

        BridgeWatchtower.Watchtower memory infoAfter = watchtower
            .getWatchtowerInfo(wt1);
        // Reporter should be slashed 50%
        assertEq(infoAfter.stake, stakeBefore / 2);
    }

    // ============= Proof Attestation =============

    function test_AttestProof_Valid() public {
        // Use 5 watchtowers so threshold = 5*6666/10000 = 3, 1 attestation won't finalize
        _registerWatchtowers(5);
        bytes32 proofHash = keccak256("proof1");
        vm.prank(wt1);
        watchtower.attestProof(proofHash, true);

        (
            uint256 attestations,
            uint256 rejections,
            bool finalized,

        ) = watchtower.getProofAttestation(proofHash);
        assertEq(attestations, 1);
        assertEq(rejections, 0);
        assertFalse(finalized);
    }

    function test_AttestProof_RevertAlreadyAttested() public {
        _registerWatchtowers(1);
        bytes32 proofHash = keccak256("proof1");
        vm.prank(wt1);
        watchtower.attestProof(proofHash, true);
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.AlreadyAttested.selector);
        watchtower.attestProof(proofHash, true);
    }

    function test_AttestProof_Finalization() public {
        // With 3 watchtowers, threshold = 3 * 6666 / 10000 = 1
        _registerWatchtowers(3);
        bytes32 proofHash = keccak256("proof_valid");
        vm.prank(wt1);
        watchtower.attestProof(proofHash, true);
        vm.prank(wt2);
        watchtower.attestProof(proofHash, true);
        (, , bool finalized, bool valid) = watchtower.getProofAttestation(
            proofHash
        );
        assertTrue(finalized);
        assertTrue(valid);
    }

    function test_AttestProof_RejectionFinalization() public {
        _registerWatchtowers(3);
        bytes32 proofHash = keccak256("proof_bad");
        vm.prank(wt1);
        watchtower.attestProof(proofHash, false);
        vm.prank(wt2);
        watchtower.attestProof(proofHash, false);
        (, , bool finalized, bool valid) = watchtower.getProofAttestation(
            proofHash
        );
        assertTrue(finalized);
        assertFalse(valid);
    }

    function test_HasConsensus() public {
        _registerWatchtowers(3);
        bytes32 proofHash = keccak256("consensus_proof");
        vm.prank(wt1);
        watchtower.attestProof(proofHash, true);
        vm.prank(wt2);
        watchtower.attestProof(proofHash, true);
        assertTrue(watchtower.hasConsensus(proofHash));
    }

    // ============= Slashing =============

    function test_Slash() public {
        vm.prank(wt1);
        watchtower.register{value: 4 ether}();
        vm.prank(admin);
        watchtower.slash(wt1, 25, "test slash");
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(info.stake, 3 ether); // 4 - 25% = 3
    }

    function test_Slash_BelowMinStake_StatusSlashed() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(admin);
        watchtower.slash(wt1, 90, "major violation");
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(
            uint8(info.status),
            uint8(BridgeWatchtower.WatchtowerStatus.SLASHED)
        );
        assertEq(watchtower.getActiveWatchtowerCount(), 0);
    }

    function test_Slash_UpdatesRewardPool() public {
        vm.prank(wt1);
        watchtower.register{value: 2 ether}();
        vm.prank(admin);
        watchtower.slash(wt1, 50, "half slash");
        assertEq(watchtower.rewardPool(), 1 ether);
    }

    function test_Slash_RevertNotSlasher() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(outsider);
        vm.expectRevert();
        watchtower.slash(wt1, 50, "unauthorized");
    }

    function test_SlashInactive() public {
        vm.prank(wt1);
        watchtower.register{value: 2 ether}();
        // Advance time past MAX_INACTIVITY (7 days)
        vm.warp(block.timestamp + 8 days);
        watchtower.slashInactive();
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        // Should lose 10% = 0.2 ether
        assertEq(info.stake, 1.8 ether);
    }

    // ============= Rewards =============

    function test_FundRewardPool() public {
        watchtower.fundRewardPool{value: 5 ether}();
        assertEq(watchtower.rewardPool(), 5 ether);
    }

    function test_ReceiveETH() public {
        (bool ok, ) = address(watchtower).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(watchtower.rewardPool(), 1 ether);
    }

    function test_ClaimRewards_RevertNoRewards() public {
        vm.prank(wt1);
        watchtower.register{value: 1 ether}();
        vm.prank(wt1);
        vm.expectRevert(BridgeWatchtower.NoRewardsAvailable.selector);
        watchtower.claimRewards();
    }

    // ============= View Functions =============

    function test_GetRequiredConfirmations() public {
        _registerWatchtowers(4);
        uint256 required = watchtower.getRequiredConfirmations();
        // Ceiling: (4 * 6666 + 9999) / 10000 = 3
        assertEq(required, 3);
    }

    function test_Constants() public view {
        assertEq(watchtower.MIN_STAKE(), 1 ether);
        assertEq(watchtower.FALSE_REPORT_SLASH_PERCENT(), 50);
        assertEq(watchtower.INACTIVITY_SLASH_PERCENT(), 10);
        assertEq(watchtower.MAX_INACTIVITY(), 7 days);
        assertEq(watchtower.EXIT_DELAY(), 14 days);
        assertEq(watchtower.CONFIRMATION_THRESHOLD_BPS(), 6666);
    }

    // ============= Fuzz =============

    function testFuzz_Register_StakeAboveMinimum(uint256 stake) public {
        stake = bound(stake, 1 ether, 100 ether);
        vm.deal(wt1, stake);
        vm.prank(wt1);
        watchtower.register{value: stake}();
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(info.stake, stake);
    }

    function testFuzz_Slash_Percent(uint256 percent) public {
        percent = bound(percent, 1, 99);
        vm.prank(wt1);
        watchtower.register{value: 10 ether}();
        vm.prank(admin);
        watchtower.slash(wt1, percent, "fuzz");
        BridgeWatchtower.Watchtower memory info = watchtower.getWatchtowerInfo(
            wt1
        );
        assertEq(info.stake, 10 ether - ((10 ether * percent) / 100));
    }

    // ============= Helpers =============

    function _registerWatchtowers(uint256 count) internal {
        address[5] memory wts = [wt1, wt2, wt3, wt4, wt5];
        for (uint256 i = 0; i < count && i < 5; i++) {
            vm.prank(wts[i]);
            watchtower.register{value: 1 ether}();
        }
    }
}
