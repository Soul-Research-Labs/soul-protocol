// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/OptimisticBridgeVerifier.sol";
import "../../contracts/security/BridgeSecurityScorecard.sol";
import "../../contracts/security/ExperimentalFeatureRegistry.sol";
import "../../contracts/security/BridgeRateLimiter.sol";
import "../../contracts/security/BridgeWatchtower.sol";

contract SecurityHardeningTest is Test {
    OptimisticBridgeVerifier public verifier;
    BridgeSecurityScorecard public scorecard;
    ExperimentalFeatureRegistry public registry;
    BridgeRateLimiter public rateLimiter;
    BridgeWatchtower public watchtower;

    address public admin = address(this);
    address public user = makeAddr("user");
    address public challenger = makeAddr("challenger");
    address public bridge = makeAddr("bridgeAdapter");

    function setUp() public {
        // Deploy contracts
        verifier = new OptimisticBridgeVerifier(admin);
        scorecard = new BridgeSecurityScorecard(admin);
        registry = new ExperimentalFeatureRegistry(admin);
        rateLimiter = new BridgeRateLimiter(admin); // This creates config but doesn't set it yet?
        watchtower = new BridgeWatchtower(admin);

        // NOTE: BridgeRateLimiter constructor sets default config, but we can override.
        // Grant roles
        rateLimiter.grantRole(rateLimiter.OPERATOR_ROLE(), admin);
        watchtower.grantRole(watchtower.WATCHTOWER_ROLE(), admin);

        // Setup Watchtower targets
        watchtower.register{value: 1 ether}(); // Register admin as watchtower
        watchtower.setTargetContracts(bridge, address(rateLimiter));
        watchtower.setReportAction(
            BridgeWatchtower.ReportType.LARGE_TRANSFER_ANOMALY,
            BridgeWatchtower.ResponseAction.TRIGGER_CIRCUIT_BREAKER
        );

        // Grant Guardian role to Watchtower in RateLimiter so it can trigger breaker
        rateLimiter.grantRole(rateLimiter.GUARDIAN_ROLE(), address(watchtower));

        // Grant Resolver role for verifier
        verifier.grantRole(verifier.RESOLVER_ROLE(), admin);
    }

    /// @notice Test Optimistic verification lifecycle
    function test_OptimisticChallenge() public {
        bytes32 msgHash = keccak256("message");
        uint256 value = 11 ether; // > optimisticThreshold (default 10)
        bytes memory proof = hex"1234";
        bytes32 commitment = bytes32(uint256(1));
        bytes32 nullifier = bytes32(uint256(2));

        // 1. Submit
        vm.deal(user, 1 ether);
        vm.prank(user);
        // Returns transferId
        bytes32 transferId = verifier.submitTransfer{value: 0.1 ether}(
            msgHash,
            value,
            proof,
            commitment,
            nullifier
        );

        // 2. Challenge
        vm.deal(challenger, 2 ether);
        vm.prank(challenger);
        verifier.challengeTransfer{value: 0.01 ether}(
            transferId,
            hex"deadbeef"
        );

        OptimisticBridgeVerifier.PendingTransfer memory t = verifier
            .getTransfer(transferId);
        assertEq(
            uint(t.status),
            uint(OptimisticBridgeVerifier.TransferStatus.CHALLENGED)
        );
        assertEq(t.challenger, challenger);

        // 3. Resolve challenge (Governance confirms challenger won -> invalid transfer)
        // resolveChallenge(transferId, proof, challengerWon)
        verifier.resolveChallenge(transferId, proof, true);

        t = verifier.getTransfer(transferId);
        assertEq(
            uint(t.status),
            uint(OptimisticBridgeVerifier.TransferStatus.REJECTED)
        );
    }

    /// @notice Test Finalization Success
    function test_OptimisticFinalization() public {
        bytes32 msgHash = keccak256("valid");
        uint256 value = 11 ether;

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 transferId = verifier.submitTransfer(
            msgHash,
            value,
            hex"",
            bytes32(0),
            bytes32(0)
        );

        // Wait period
        vm.warp(block.timestamp + 1 hours + 1 seconds);

        verifier.finalizeTransfer(transferId);

        OptimisticBridgeVerifier.PendingTransfer memory t = verifier
            .getTransfer(transferId);
        assertEq(
            uint(t.status),
            uint(OptimisticBridgeVerifier.TransferStatus.FINALIZED)
        );
    }

    /// @notice Test Scorecard logic
    function test_Scorecard() public {
        // Initial check
        assertFalse(scorecard.isBridgeSafe(bridge));

        // Update score to safe levels
        // 15, 15, 15, 15, 15 = 75 total (Threshold 70)
        scorecard.updateScore(bridge, 15, 15, 15, 15, 15);

        assertTrue(scorecard.isBridgeSafe(bridge));

        // Update to unsafe
        scorecard.updateScore(bridge, 10, 10, 10, 10, 10); // 50 total
        assertFalse(scorecard.isBridgeSafe(bridge));
    }

    /// @notice Test Feature Registry
    function test_FeatureRegistry() public {
        bytes32 featureId = registry.FHE_OPERATIONS();

        // Default is disabled
        assertFalse(registry.isFeatureEnabled(featureId));

        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureRegistry.FeatureDisabled.selector,
                featureId
            )
        );
        registry.requireFeatureEnabled(featureId);

        // Enable experimental
        registry.updateFeatureStatus(
            featureId,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        assertTrue(registry.isFeatureEnabled(featureId));

        // Check risk limit
        ExperimentalFeatureRegistry.Feature memory f = registry.getFeature(
            featureId
        );
        assertEq(f.maxValueLocked, 1 ether);
    }

    /// @notice Test Anomaly Detection in Rate Limiter
    function test_AnomalyDetection() public {
        address anomalousUser = makeAddr("anomalous");

        // 1. Establish baseline (normal behavior)
        // Send 10 ETH, 10 ETH, 10 ETH
        rateLimiter.recordTransfer(anomalousUser, 10 ether);
        rateLimiter.recordTransfer(anomalousUser, 10 ether);
        rateLimiter.recordTransfer(anomalousUser, 10 ether);

        // 2. Trigger anomaly
        // Send 100 ETH (Should be > 3 sigma away from 10)

        // We expect AnomalyDetected event but it's internal logic mostly.
        // We check circuit breaker status.

        rateLimiter.recordTransfer(anomalousUser, 100 ether);

        // SECURITY FIX H-7: anomaly detection now blacklists the offending user
        // instead of triggering the global circuit breaker (prevents DoS)
        assertTrue(
            rateLimiter.blacklisted(anomalousUser),
            "Anomalous user should be blacklisted"
        );
        assertFalse(
            rateLimiter.isCircuitBreakerActive(),
            "Circuit breaker should NOT be triggered (user isolation, not global pause)"
        );
    }

    /// @notice Test Watchtower Automated Action
    function test_WatchtowerAutomatedAction() public {
        // Register watchtower
        address wt = makeAddr("wt");
        vm.deal(wt, 10 ether);
        vm.prank(wt);
        watchtower.register{value: 1 ether}();

        // Note: admin is already a watchtower from setup, so we have 2 now.

        bytes32 subject = keccak256("exploit");

        // 1. Admin submits report
        bytes32 reportId = watchtower.submitReport(
            BridgeWatchtower.ReportType.LARGE_TRANSFER_ANOMALY,
            subject,
            ""
        );

        // 2. WT votes
        vm.prank(wt);
        watchtower.voteOnReport(reportId, true);

        // Should be finalized and action executed
        BridgeWatchtower.AnomalyReport memory r = watchtower.getReport(
            reportId
        );
        assertEq(uint(r.status), uint(BridgeWatchtower.ReportStatus.CONFIRMED));

        // Check action execution (RateLimiter triggered)
        assertTrue(
            rateLimiter.isCircuitBreakerActive(),
            "Circuit breaker should be active via watchtower"
        );
        (, , string memory reason, ) = rateLimiter.breakerStatus();
        assertEq(reason, "Watchtower Alert");
    }
}
