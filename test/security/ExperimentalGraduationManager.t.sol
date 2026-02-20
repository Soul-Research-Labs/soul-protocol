// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";
import {ExperimentalGraduationManager} from "../../contracts/security/ExperimentalGraduationManager.sol";

/// @dev Shared base with setUp and helpers — split into multiple contracts to avoid Yul stack-too-deep
abstract contract GraduationTestBase is Test {
    ExperimentalFeatureRegistry public registry;
    ExperimentalGraduationManager public manager;

    address public admin = makeAddr("admin");
    address public proposer = makeAddr("proposer");
    address public executor = makeAddr("executor");
    address public auditor = makeAddr("auditor");
    address public ciBot = makeAddr("ciBot");
    address public securityReviewer = makeAddr("securityReviewer");
    address public attacker = makeAddr("attacker");

    bytes32 public constant FEATURE_ADMIN = keccak256("FEATURE_ADMIN");
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant CI_ROLE = keccak256("CI_ROLE");
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    bytes32 public fheId;
    bytes32 public pqcId;
    bytes32 public mpcId;

    function setUp() public virtual {
        vm.startPrank(admin);
        registry = new ExperimentalFeatureRegistry(admin);
        manager = new ExperimentalGraduationManager(address(registry), admin);
        registry.grantRole(FEATURE_ADMIN, address(manager));
        manager.grantRole(PROPOSER_ROLE, proposer);
        manager.grantRole(EXECUTOR_ROLE, executor);
        manager.grantRole(AUDITOR_ROLE, auditor);
        manager.grantRole(CI_ROLE, ciBot);
        manager.grantRole(SECURITY_ROLE, securityReviewer);
        vm.stopPrank();

        fheId = registry.FHE_OPERATIONS();
        pqcId = registry.PQC_SIGNATURES();
        mpcId = registry.MPC_THRESHOLD();
    }

    function _stdCriteria()
        internal
        pure
        returns (ExperimentalGraduationManager.GraduationCriteria memory)
    {
        return
            ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: 7 days,
                minTestCount: 20,
                minFuzzRuns: 1000,
                requiresAuditAttestation: true,
                requiresSecurityReview: true,
                requiresCertoraSpec: false
            });
    }

    function _easyCriteria()
        internal
        pure
        returns (ExperimentalGraduationManager.GraduationCriteria memory)
    {
        return
            ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: 1 hours,
                minTestCount: 0,
                minFuzzRuns: 0,
                requiresAuditAttestation: false,
                requiresSecurityReview: false,
                requiresCertoraSpec: false
            });
    }

    function _getFeatureStatus(
        bytes32 fid
    ) internal view returns (ExperimentalFeatureRegistry.FeatureStatus) {
        (, ExperimentalFeatureRegistry.FeatureStatus s, , , , , , , ) = registry
            .features(fid);
        return s;
    }

    function _moveToBeta(bytes32 fid) internal {
        vm.startPrank(admin);
        registry.updateFeatureStatus(
            fid,
            ExperimentalFeatureRegistry.FeatureStatus.EXPERIMENTAL
        );
        registry.updateFeatureStatus(
            fid,
            ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
        manager.recordBetaEntry(fid);
        vm.stopPrank();
    }

    function _fullyAttest(bytes32 fid) internal {
        vm.prank(admin);
        manager.setCriteria(fid, _stdCriteria());

        vm.prank(auditor);
        manager.attestAudit(fid, keccak256("audit-report-v1"));

        vm.prank(ciBot);
        manager.attestTestCoverage(fid, 50, 10000, keccak256("ci-log"));

        vm.prank(securityReviewer);
        manager.attestSecurityReview(fid, keccak256("security-review"));
    }

    function _prepareGraduation(
        bytes32 fid
    ) internal returns (uint256 proposalId) {
        _moveToBeta(fid);
        _fullyAttest(fid);
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(proposer);
        proposalId = manager.proposeGraduation(fid);
    }

    function _graduateFeature(
        bytes32 fid
    ) internal returns (uint256 proposalId) {
        proposalId = _prepareGraduation(fid);
        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(executor);
        manager.executeGraduation(proposalId);
    }

    function _getProposalStatus(
        uint256 pid
    ) internal view returns (ExperimentalGraduationManager.ProposalStatus) {
        (, ExperimentalGraduationManager.ProposalStatus s, , , ) = manager
            .proposals(pid);
        return s;
    }
}

/*//////////////////////////////////////////////////////////////
             CONSTRUCTOR & CRITERIA & BETA ENTRY TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationConstructorTest is GraduationTestBase {
    function test_constructor_setsRegistry() public view {
        assertEq(address(manager.registry()), address(registry));
    }

    function test_constructor_setsDefaultTimelock() public view {
        assertEq(manager.timelockDuration(), 3 days);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(manager.hasRole(manager.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(manager.hasRole(PROPOSER_ROLE, admin));
        assertTrue(manager.hasRole(EXECUTOR_ROLE, admin));
    }

    function test_constructor_revertsOnZeroRegistry() public {
        vm.expectRevert(ExperimentalGraduationManager.ZeroAddress.selector);
        new ExperimentalGraduationManager(address(0), admin);
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(ExperimentalGraduationManager.ZeroAddress.selector);
        new ExperimentalGraduationManager(address(registry), address(0));
    }
}

contract GraduationCriteriaTest is GraduationTestBase {
    function test_setCriteria_success() public {
        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        assertTrue(manager.criteriaConfigured(fheId));
        (
            uint48 minTime,
            uint32 minTests,
            uint32 minFuzz,
            bool rAudit,
            bool rSec,
            bool rCert
        ) = manager.criteria(fheId);

        assertEq(minTime, 7 days);
        assertEq(minTests, 20);
        assertEq(minFuzz, 1000);
        assertTrue(rAudit);
        assertTrue(rSec);
        assertFalse(rCert);
    }

    function test_setCriteria_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        manager.setCriteria(fheId, _stdCriteria());
    }

    function test_setCriteria_canUpdate() public {
        vm.startPrank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        ExperimentalGraduationManager.GraduationCriteria
            memory strict = ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: 30 days,
                minTestCount: 100,
                minFuzzRuns: 50000,
                requiresAuditAttestation: true,
                requiresSecurityReview: true,
                requiresCertoraSpec: true
            });
        manager.setCriteria(fheId, strict);
        vm.stopPrank();

        (uint48 minTime, , , , , bool certora) = manager.criteria(fheId);
        assertEq(minTime, 30 days);
        assertTrue(certora);
    }

    function test_recordBetaEntry_success() public {
        vm.prank(admin);
        manager.recordBetaEntry(fheId);

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.betaEntryTimestamp, uint48(block.timestamp));
    }

    function test_recordBetaEntry_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        manager.recordBetaEntry(fheId);
    }
}

/*//////////////////////////////////////////////////////////////
                      ATTESTATION TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationAttestationTest is GraduationTestBase {
    function test_attestAudit_success() public {
        bytes32 reportHash = keccak256("audit-report");
        vm.prank(auditor);
        manager.attestAudit(fheId, reportHash);

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.auditAttestation.attester, auditor);
        assertEq(grad.auditAttestation.evidenceHash, reportHash);
        assertGt(grad.auditAttestation.attestedAt, 0);
    }

    function test_attestAudit_revertsForNonAuditor() public {
        vm.prank(attacker);
        vm.expectRevert();
        manager.attestAudit(fheId, keccak256("fake"));
    }

    function test_attestTestCoverage_success() public {
        vm.prank(ciBot);
        manager.attestTestCoverage(fheId, 100, 10000, keccak256("ci-log"));

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.reportedTestCount, 100);
        assertEq(grad.reportedFuzzRuns, 10000);
        assertEq(grad.testAttestation.attester, ciBot);
    }

    function test_attestTestCoverage_revertsForNonCI() public {
        vm.prank(attacker);
        vm.expectRevert();
        manager.attestTestCoverage(fheId, 100, 10000, keccak256("fake"));
    }

    function test_attestSecurityReview_success() public {
        vm.prank(securityReviewer);
        manager.attestSecurityReview(fheId, keccak256("review"));

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.securityAttestation.attester, securityReviewer);
    }

    function test_attestCertoraSpec_success() public {
        vm.prank(securityReviewer);
        manager.attestCertoraSpec(fheId, keccak256("spec"));

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.certoraAttestation.attester, securityReviewer);
    }

    function test_attestation_canBeOverwritten() public {
        vm.startPrank(auditor);
        manager.attestAudit(fheId, keccak256("v1"));
        manager.attestAudit(fheId, keccak256("v2"));
        vm.stopPrank();

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.auditAttestation.evidenceHash, keccak256("v2"));
    }
}

/*//////////////////////////////////////////////////////////////
                  GRADUATION PROPOSAL TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationProposalTest is GraduationTestBase {
    function test_proposeGraduation_success() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(proposer);
        uint256 pid = manager.proposeGraduation(fheId);

        assertEq(pid, 1);
        assertEq(manager.proposalCount(), 1);
        assertEq(manager.activeProposal(fheId), 1);
        assertTrue(
            _getProposalStatus(pid) ==
                ExperimentalGraduationManager.ProposalStatus.PENDING
        );
    }

    function test_proposeGraduation_proposalFields() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(proposer);
        uint256 pid = manager.proposeGraduation(fheId);

        (
            bytes32 fid,
            ,
            address prop,
            uint48 proposedAt,
            uint48 execAfter
        ) = manager.proposals(pid);
        assertEq(fid, fheId);
        assertEq(prop, proposer);
        assertEq(execAfter, proposedAt + 3 days);
    }

    function test_proposeGraduation_revertsIfNotBeta() public {
        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.FeatureNotInBeta.selector,
                fheId
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsIfCriteriaNotSet() public {
        _moveToBeta(fheId);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.CriteriaNotSet.selector,
                fheId
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsIfInsufficientTimeInBeta() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.CriteriaNotMet.selector,
                fheId,
                "Insufficient time in beta"
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsIfMissingAudit() public {
        _moveToBeta(fheId);

        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        vm.prank(ciBot);
        manager.attestTestCoverage(fheId, 50, 10000, keccak256("ci"));

        vm.prank(securityReviewer);
        manager.attestSecurityReview(fheId, keccak256("review"));

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.CriteriaNotMet.selector,
                fheId,
                "Missing audit attestation"
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsIfInsufficientTests() public {
        _moveToBeta(fheId);

        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        vm.prank(ciBot);
        manager.attestTestCoverage(fheId, 5, 10000, keccak256("ci"));

        vm.prank(auditor);
        manager.attestAudit(fheId, keccak256("audit"));

        vm.prank(securityReviewer);
        manager.attestSecurityReview(fheId, keccak256("review"));

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.CriteriaNotMet.selector,
                fheId,
                "Insufficient test count"
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsIfActiveProposal() public {
        _prepareGraduation(fheId);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.ProposalAlreadyActive.selector,
                fheId
            )
        );
        manager.proposeGraduation(fheId);
    }

    function test_proposeGraduation_revertsForNonProposer() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(attacker);
        vm.expectRevert();
        manager.proposeGraduation(fheId);
    }
}

/*//////////////////////////////////////////////////////////////
              GRADUATION EXECUTION & CANCELLATION TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationExecutionTest is GraduationTestBase {
    function test_executeGraduation_success() public {
        uint256 pid = _graduateFeature(fheId);

        assertTrue(
            _getProposalStatus(pid) ==
                ExperimentalGraduationManager.ProposalStatus.EXECUTED
        );
        assertTrue(
            _getFeatureStatus(fheId) ==
                ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
        assertEq(manager.activeProposal(fheId), 0);
    }

    function test_executeGraduation_setsMetadata() public {
        _graduateFeature(fheId);

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertGt(grad.graduatedAt, 0);
        assertEq(grad.graduationCount, 1);
    }

    function test_executeGraduation_revertsBeforeTimelock() public {
        uint256 pid = _prepareGraduation(fheId);
        vm.warp(block.timestamp + 1 days);

        vm.prank(executor);
        vm.expectRevert();
        manager.executeGraduation(pid);
    }

    function test_executeGraduation_revertsIfNotPending() public {
        uint256 pid = _prepareGraduation(fheId);

        vm.prank(admin);
        manager.cancelGraduation(pid, "changed mind");

        vm.warp(block.timestamp + 3 days + 1);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.ProposalNotPending.selector,
                pid
            )
        );
        manager.executeGraduation(pid);
    }

    function test_executeGraduation_revertsForNonExecutor() public {
        uint256 pid = _prepareGraduation(fheId);
        vm.warp(block.timestamp + 3 days + 1);

        vm.prank(attacker);
        vm.expectRevert();
        manager.executeGraduation(pid);
    }

    function test_cancelGraduation_success() public {
        uint256 pid = _prepareGraduation(fheId);

        vm.prank(admin);
        manager.cancelGraduation(pid, "Security concern");

        assertTrue(
            _getProposalStatus(pid) ==
                ExperimentalGraduationManager.ProposalStatus.CANCELLED
        );
        assertEq(manager.activeProposal(fheId), 0);
    }

    function test_cancelGraduation_allowsNewProposal() public {
        uint256 pid1 = _prepareGraduation(fheId);

        vm.prank(admin);
        manager.cancelGraduation(pid1, "Redo");

        vm.prank(proposer);
        uint256 pid2 = manager.proposeGraduation(fheId);
        assertEq(pid2, 2);
    }

    function test_cancelGraduation_revertsIfNotPending() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.ProposalNotPending.selector,
                999
            )
        );
        manager.cancelGraduation(999, "doesn't exist");
    }

    function test_cancelGraduation_revertsForNonAdmin() public {
        uint256 pid = _prepareGraduation(fheId);

        vm.prank(attacker);
        vm.expectRevert();
        manager.cancelGraduation(pid, "hijack");
    }
}

/*//////////////////////////////////////////////////////////////
                       DEMOTION TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationDemotionTest is GraduationTestBase {
    function test_demoteFeature_success() public {
        _graduateFeature(fheId);

        vm.prank(admin);
        manager.demoteFeature(fheId, "Vulnerability found");

        assertTrue(
            _getFeatureStatus(fheId) ==
                ExperimentalFeatureRegistry.FeatureStatus.BETA
        );
    }

    function test_demoteFeature_setsMetadata() public {
        _graduateFeature(fheId);

        vm.prank(admin);
        manager.demoteFeature(fheId, "Vulnerability found");

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertGt(grad.demotedAt, 0);
        assertEq(grad.demotionCount, 1);
        assertEq(
            keccak256(bytes(grad.demotionReason)),
            keccak256("Vulnerability found")
        );
    }

    function test_demoteFeature_clearsAttestations() public {
        _graduateFeature(fheId);

        vm.prank(admin);
        manager.demoteFeature(fheId, "Vulnerability found");

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.auditAttestation.attestedAt, 0);
        assertEq(grad.testAttestation.attestedAt, 0);
        assertEq(grad.securityAttestation.attestedAt, 0);
    }

    function test_demoteFeature_revertsIfNotProduction() public {
        _moveToBeta(fheId);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.FeatureNotInProduction.selector,
                fheId
            )
        );
        manager.demoteFeature(fheId, "not in production");
    }

    function test_demoteFeature_revertsForNonAdmin() public {
        _graduateFeature(fheId);

        vm.prank(attacker);
        vm.expectRevert();
        manager.demoteFeature(fheId, "hijack");
    }

    function test_demoteFeature_canReGraduate() public {
        _graduateFeature(fheId);

        vm.prank(admin);
        manager.demoteFeature(fheId, "Issue found");

        // Re-attest and re-graduate
        _fullyAttest(fheId);
        vm.prank(admin);
        manager.recordBetaEntry(fheId);
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(proposer);
        uint256 p2 = manager.proposeGraduation(fheId);

        vm.warp(block.timestamp + 3 days + 1);
        vm.prank(executor);
        manager.executeGraduation(p2);

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.graduationCount, 2);
        assertEq(grad.demotionCount, 1);
    }
}

/*//////////////////////////////////////////////////////////////
              TIMELOCK & VIEW FUNCTION TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationTimelockViewTest is GraduationTestBase {
    function test_setTimelockDuration_success() public {
        vm.prank(admin);
        manager.setTimelockDuration(7 days);
        assertEq(manager.timelockDuration(), 7 days);
    }

    function test_setTimelockDuration_revertsOnTooShort() public {
        vm.prank(admin);
        vm.expectRevert(
            ExperimentalGraduationManager.InvalidTimelockDuration.selector
        );
        manager.setTimelockDuration(30 minutes);
    }

    function test_setTimelockDuration_revertsOnTooLong() public {
        vm.prank(admin);
        vm.expectRevert(
            ExperimentalGraduationManager.InvalidTimelockDuration.selector
        );
        manager.setTimelockDuration(60 days);
    }

    function test_setTimelockDuration_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        manager.setTimelockDuration(7 days);
    }

    function test_isGraduationReady_trueWhenAllCriteriaMet() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);
        vm.warp(block.timestamp + 7 days + 1);
        assertTrue(manager.isGraduationReady(fheId));
    }

    function test_isGraduationReady_falseWhenCriteriaNotSet() public view {
        assertFalse(manager.isGraduationReady(fheId));
    }

    function test_isGraduationReady_falseWhenMissingAttestation() public {
        _moveToBeta(fheId);

        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        vm.prank(auditor);
        manager.attestAudit(fheId, keccak256("audit"));

        vm.warp(block.timestamp + 7 days + 1);
        assertFalse(manager.isGraduationReady(fheId));
    }

    function test_getGraduationProgress_showsBreakdown() public {
        _moveToBeta(fheId);

        vm.prank(admin);
        manager.setCriteria(fheId, _stdCriteria());

        vm.prank(auditor);
        manager.attestAudit(fheId, keccak256("audit"));

        vm.prank(ciBot);
        manager.attestTestCoverage(fheId, 50, 10000, keccak256("ci"));

        (
            bool timeMet,
            bool testsMet,
            bool fuzzMet,
            bool auditMet,
            bool securityMet,
            bool certoraMet
        ) = manager.getGraduationProgress(fheId);

        assertFalse(timeMet);
        assertTrue(testsMet);
        assertTrue(fuzzMet);
        assertTrue(auditMet);
        assertFalse(securityMet);
        assertTrue(certoraMet);
    }

    function test_getGraduationProgress_afterTimeWarp() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);
        vm.warp(block.timestamp + 7 days + 1);

        (
            bool timeMet,
            bool testsMet,
            bool fuzzMet,
            bool auditMet,
            bool securityMet,
            bool certoraMet
        ) = manager.getGraduationProgress(fheId);

        assertTrue(timeMet);
        assertTrue(testsMet);
        assertTrue(fuzzMet);
        assertTrue(auditMet);
        assertTrue(securityMet);
        assertTrue(certoraMet);
    }

    function test_getGraduation_returnsFullState() public {
        _moveToBeta(fheId);
        _fullyAttest(fheId);

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertGt(grad.betaEntryTimestamp, 0);
        assertEq(grad.auditAttestation.attester, auditor);
        assertEq(grad.reportedTestCount, 50);
        assertEq(grad.reportedFuzzRuns, 10000);
    }
}

/*//////////////////////////////////////////////////////////////
         CERTORA, MINIMAL, MULTI-FEATURE, & FUZZ TESTS
//////////////////////////////////////////////////////////////*/

contract GraduationAdvancedTest is GraduationTestBase {
    function test_proposeGraduation_revertsWithoutCertoraSpec() public {
        _moveToBeta(pqcId);

        ExperimentalGraduationManager.GraduationCriteria
            memory strict = ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: 1 days,
                minTestCount: 1,
                minFuzzRuns: 1,
                requiresAuditAttestation: false,
                requiresSecurityReview: false,
                requiresCertoraSpec: true
            });

        vm.prank(admin);
        manager.setCriteria(pqcId, strict);

        vm.prank(ciBot);
        manager.attestTestCoverage(pqcId, 10, 1000, keccak256("ci"));

        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalGraduationManager.CriteriaNotMet.selector,
                pqcId,
                "Missing Certora spec"
            )
        );
        manager.proposeGraduation(pqcId);
    }

    function test_proposeGraduation_passesWithCertoraSpec() public {
        _moveToBeta(pqcId);

        ExperimentalGraduationManager.GraduationCriteria
            memory strict = ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: 1 days,
                minTestCount: 1,
                minFuzzRuns: 1,
                requiresAuditAttestation: false,
                requiresSecurityReview: false,
                requiresCertoraSpec: true
            });

        vm.prank(admin);
        manager.setCriteria(pqcId, strict);

        vm.prank(ciBot);
        manager.attestTestCoverage(pqcId, 10, 1000, keccak256("ci"));

        vm.prank(securityReviewer);
        manager.attestCertoraSpec(pqcId, keccak256("spec"));

        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(proposer);
        uint256 pid = manager.proposeGraduation(pqcId);
        assertGt(pid, 0);
    }

    function test_graduation_withMinimalCriteria() public {
        _moveToBeta(mpcId);

        vm.prank(admin);
        manager.setCriteria(mpcId, _easyCriteria());

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(proposer);
        uint256 pid = manager.proposeGraduation(mpcId);

        vm.warp(block.timestamp + 3 days + 1);

        vm.prank(executor);
        manager.executeGraduation(pid);

        assertTrue(
            _getFeatureStatus(mpcId) ==
                ExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );
    }

    function test_multipleFeatures_independentProposals() public {
        _moveToBeta(fheId);
        _moveToBeta(pqcId);

        vm.startPrank(admin);
        manager.setCriteria(fheId, _easyCriteria());
        manager.setCriteria(pqcId, _easyCriteria());
        vm.stopPrank();

        vm.warp(block.timestamp + 1 hours + 1);

        vm.startPrank(proposer);
        uint256 p1 = manager.proposeGraduation(fheId);
        uint256 p2 = manager.proposeGraduation(pqcId);
        vm.stopPrank();

        assertEq(p1, 1);
        assertEq(p2, 2);
        assertEq(manager.activeProposal(fheId), 1);
        assertEq(manager.activeProposal(pqcId), 2);
    }

    function testFuzz_setTimelockDuration_valid(uint48 duration) public {
        duration = uint48(bound(duration, 1 hours, 30 days));
        vm.prank(admin);
        manager.setTimelockDuration(duration);
        assertEq(manager.timelockDuration(), duration);
    }

    function testFuzz_attestTestCoverage_variousValues(
        uint32 tests,
        uint32 fuzz
    ) public {
        tests = uint32(bound(tests, 0, 10000));
        fuzz = uint32(bound(fuzz, 0, 100000));

        vm.prank(ciBot);
        manager.attestTestCoverage(fheId, tests, fuzz, keccak256("ci"));

        ExperimentalGraduationManager.FeatureGraduation memory grad = manager
            .getGraduation(fheId);
        assertEq(grad.reportedTestCount, tests);
        assertEq(grad.reportedFuzzRuns, fuzz);
    }

    function testFuzz_graduationTimelockRespected(uint48 extraWait) public {
        extraWait = uint48(bound(extraWait, 0, 30 days));

        uint256 pid = _prepareGraduation(fheId);
        (, , , , uint48 executableAfter) = manager.proposals(pid);

        vm.warp(executableAfter - 1);
        vm.prank(executor);
        vm.expectRevert();
        manager.executeGraduation(pid);

        vm.warp(executableAfter + extraWait);
        vm.prank(executor);
        manager.executeGraduation(pid);

        assertTrue(
            _getProposalStatus(pid) ==
                ExperimentalGraduationManager.ProposalStatus.EXECUTED
        );
    }

    function testFuzz_minTimeInBeta_boundary(uint48 betaTime) public {
        betaTime = uint48(bound(betaTime, 2, 365 days));

        _moveToBeta(fheId);

        ExperimentalGraduationManager.GraduationCriteria
            memory crit = ExperimentalGraduationManager.GraduationCriteria({
                minTimeInBeta: betaTime,
                minTestCount: 0,
                minFuzzRuns: 0,
                requiresAuditAttestation: false,
                requiresSecurityReview: false,
                requiresCertoraSpec: false
            });

        vm.prank(admin);
        manager.setCriteria(fheId, crit);

        // Before time passes — should fail
        (bool timeMet1, , , , , ) = manager.getGraduationProgress(fheId);
        assertFalse(timeMet1);

        // After time passes — should pass
        vm.warp(block.timestamp + betaTime + 1);
        (bool timeMet2, , , , , ) = manager.getGraduationProgress(fheId);
        assertTrue(timeMet2);
    }
}
