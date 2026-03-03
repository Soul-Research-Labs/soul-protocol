// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PQCPrecompileRouter} from "../../contracts/experimental/verifiers/PQCPrecompileRouter.sol";
import {OnChainPQCVerifier} from "../../contracts/experimental/verifiers/OnChainPQCVerifier.sol";
import {STARKVerifierRouter} from "../../contracts/experimental/verifiers/STARKVerifierRouter.sol";
import {PoseidonCommitmentManager} from "../../contracts/experimental/privacy/PoseidonCommitmentManager.sol";
import {PQCGraduationManager} from "../../contracts/experimental/privacy/PQCGraduationManager.sol";
import {PQCNativeStealth} from "../../contracts/experimental/privacy/PQCNativeStealth.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

// ═══════════════════════════════════════════════════════════════════════
//                  MOCK CONTRACTS FOR TESTING
// ═══════════════════════════════════════════════════════════════════════

/// @dev Mock Feature Registry for graduation tests
contract MockFeatureRegistry {
    mapping(bytes32 => uint8) public featureStatus;
    mapping(bytes32 => uint256) public riskLimits;

    function updateFeatureStatus(bytes32 featureId, uint8 status) external {
        featureStatus[featureId] = status;
    }

    function updateRiskLimit(bytes32 featureId, uint256 limit) external {
        riskLimits[featureId] = limit;
    }
}

/// @dev Mock HybridPQCVerifier for Phase 3 tests
contract MockHybridPQCVerifier {
    mapping(bytes32 => bool) public approvedPQCResults;

    function submitPQCResult(bytes32 resultHash) external {
        approvedPQCResults[resultHash] = true;
    }

    function setApproved(bytes32 h, bool v) external {
        approvedPQCResults[h] = v;
    }
}

/// @dev Mock FalconZKVerifier for stealth tests
contract MockFalconZKVerifier {
    mapping(bytes32 => bool) public verifiedProofs;

    function isProofVerified(bytes32 h) external view returns (bool) {
        return verifiedProofs[h];
    }

    function setVerified(bytes32 h, bool v) external {
        verifiedProofs[h] = v;
    }
}

/// @dev Mock STARK verifier contract
contract MockSTARKVerifier {
    bool public shouldVerify = true;

    function verifyProof(bytes calldata) external view returns (bool) {
        return shouldVerify;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }
}

/// @dev Mock classical verifier
contract MockClassicalVerifier {
    bool public shouldVerify = true;

    function verify(bytes calldata) external view returns (bool) {
        return shouldVerify;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }
}

/// @dev Mock Pedersen verifier
contract MockPedersenVerifier {
    bool public shouldVerify = true;

    function verifyCommitment(bytes calldata) external view returns (bool) {
        return shouldVerify;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }
}

/// @dev Mock Poseidon verifier
contract MockPoseidonVerifier {
    bool public shouldVerify = true;

    function verifyCommitment(bytes calldata) external view returns (bool) {
        return shouldVerify;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }
}

/// @dev Mock precompile (returns true for any verification call)
contract MockPrecompile {
    fallback() external {
        assembly {
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}

/// @dev Mock PQCStealthIntegration (legacy) for migration tests
contract MockLegacyPQCStealth {
    struct PQCStealthMeta {
        bytes pqcSpendingPubKey;
        bytes pqcViewingPubKey;
        uint8 sigAlgorithm;
        uint8 kemVariant;
        bytes32 spendingKeyHash;
        bytes32 viewingKeyHash;
        uint256 registeredAt;
        bool active;
    }

    mapping(address => PQCStealthMeta) public pqcMetaAddresses;

    function setMeta(
        address owner,
        bytes32 spendHash,
        bytes32 viewHash,
        bool active
    ) external {
        pqcMetaAddresses[owner] = PQCStealthMeta({
            pqcSpendingPubKey: new bytes(897),
            pqcViewingPubKey: new bytes(1184),
            sigAlgorithm: 0,
            kemVariant: 1,
            spendingKeyHash: spendHash,
            viewingKeyHash: viewHash,
            registeredAt: block.timestamp,
            active: active
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 1: PQCPrecompileRouter
// ═══════════════════════════════════════════════════════════════════════

contract PQCPrecompileRouterTest is Test {
    PQCPrecompileRouter public router;
    MockHybridPQCVerifier public mockVerifier;
    MockFalconZKVerifier public mockFalcon;
    MockPrecompile public mockPrecompile;

    address admin;
    address operator;
    address user1;

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        user1 = makeAddr("user1");
        mockVerifier = new MockHybridPQCVerifier();
        mockFalcon = new MockFalconZKVerifier();
        mockPrecompile = new MockPrecompile();

        vm.startPrank(admin);
        router = new PQCPrecompileRouter(
            admin,
            address(mockVerifier),
            address(mockFalcon)
        );
        router.grantRole(router.OPERATOR_ROLE(), operator);
        router.grantRole(router.PRECOMPILE_ADMIN_ROLE(), admin);
        router.grantRole(router.PAUSER_ROLE(), admin);
        vm.stopPrank();
    }

    function test_InitialState() public view {
        assertEq(router.hybridPQCVerifier(), address(mockVerifier));
        assertEq(router.falconZKVerifier(), address(mockFalcon));
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_ConfigurePrecompile() public {
        vm.prank(admin);
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            address(mockPrecompile),
            false
        );

        (
            address precompileAddr,
            PQCPrecompileRouter.PrecompileStatus status,
            uint256 totalCalls,
            ,

        ) = router.getPrecompileStats(IPQCVerifier.PQCAlgorithm.FN_DSA_512);
        assertEq(precompileAddr, address(mockPrecompile));
        assertEq(totalCalls, 0);
        assertEq(
            uint8(status),
            uint8(PQCPrecompileRouter.PrecompileStatus.UNKNOWN)
        );
    }

    function test_RevertNonAdminConfigurePrecompile() public {
        vm.prank(user1);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            address(mockPrecompile),
            false
        );
    }

    function test_ConfigureFallbackChain() public {
        vm.prank(admin);
        router.configureFallbackChain(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCPrecompileRouter.VerificationBackend.ZK_PROOF,
            PQCPrecompileRouter.VerificationBackend.PRECOMPILE,
            PQCPrecompileRouter.VerificationBackend.ORACLE,
            true
        );
    }

    function test_RevertDuplicateBackendsInFallback() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configureFallbackChain(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            PQCPrecompileRouter.VerificationBackend.ZK_PROOF,
            PQCPrecompileRouter.VerificationBackend.ZK_PROOF, // duplicate
            PQCPrecompileRouter.VerificationBackend.ORACLE,
            true
        );
    }

    function test_ProbePrecompileUnavailable() public {
        vm.prank(operator);
        PQCPrecompileRouter.PrecompileStatus status = router.probePrecompile(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );
        assertEq(
            uint8(status),
            uint8(PQCPrecompileRouter.PrecompileStatus.UNAVAILABLE)
        );
    }

    function test_SetHybridPQCVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        router.setHybridPQCVerifier(newVerifier);
        assertEq(router.hybridPQCVerifier(), newVerifier);
    }

    function test_RevertSetZeroVerifier() public {
        vm.prank(admin);
        vm.expectRevert();
        router.setHybridPQCVerifier(address(0));
    }

    function test_SetFalconZKVerifier() public {
        address newAddr = makeAddr("newFalcon");
        vm.prank(admin);
        router.setFalconZKVerifier(newAddr);
        assertEq(router.falconZKVerifier(), newAddr);
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        router.pause();
        assertTrue(router.paused());
        vm.prank(admin); // unpause requires DEFAULT_ADMIN_ROLE
        router.unpause();
        assertFalse(router.paused());
    }

    function test_GetRoutingStats() public view {
        (
            uint256 totalRouted,
            uint256 precompileSuccesses,
            uint256 fallbacks,
            uint256 precompileRate
        ) = router.getRoutingStats();
        assertEq(totalRouted, 0);
        assertEq(precompileSuccesses, 0);
        assertEq(fallbacks, 0);
        assertEq(precompileRate, 0);
    }

    function test_RevertConfigurePrecompileZeroAddr() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            address(0),
            false
        );
    }

    function test_RevertConfigureKEMAlgorithm() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.ML_KEM_512,
            address(mockPrecompile),
            false
        );
    }

    function test_IsProbeFresh() public view {
        bool fresh = router.isProbeFresh(IPQCVerifier.PQCAlgorithm.FN_DSA_512);
        assertFalse(fresh); // No probe done yet
    }

    function test_ComputeResultHash() public view {
        bytes32 hash = router.computeResultHash(
            keccak256("msg"),
            keccak256("sig"),
            address(0x1234),
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );
        assertTrue(hash != bytes32(0));
    }

    function test_RevertKEMAlgorithm_ML_KEM_512() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.ML_KEM_512,
            address(mockPrecompile),
            false
        );
    }

    function test_RevertKEMAlgorithm_ML_KEM_768() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            address(mockPrecompile),
            false
        );
    }

    function test_RevertKEMAlgorithm_ML_KEM_1024() public {
        vm.prank(admin);
        vm.expectRevert();
        router.configurePrecompile(
            IPQCVerifier.PQCAlgorithm.ML_KEM_1024,
            address(mockPrecompile),
            false
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 2: OnChainPQCVerifier
// ═══════════════════════════════════════════════════════════════════════

contract OnChainPQCVerifierTest is Test {
    OnChainPQCVerifier public verifier;
    MockHybridPQCVerifier public mockHub;

    address admin;
    address operator;
    address user1;

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        user1 = makeAddr("user1");
        mockHub = new MockHybridPQCVerifier();

        vm.startPrank(admin);
        verifier = new OnChainPQCVerifier(admin, address(mockHub));
        verifier.grantRole(verifier.OPERATOR_ROLE(), operator);
        verifier.grantRole(verifier.VERIFIER_ADMIN_ROLE(), admin);
        verifier.grantRole(verifier.PAUSER_ROLE(), admin);
        vm.stopPrank();
    }

    function test_InitialState() public view {
        assertEq(verifier.hybridPQCVerifier(), address(mockHub));
        assertEq(
            uint8(verifier.oracleDeprecationStage()),
            uint8(OnChainPQCVerifier.OracleDeprecationStage.ACTIVE)
        );
    }

    function test_ConfigureAlgorithm() public {
        address precompile = makeAddr("precompile");
        address zkVerifier = makeAddr("zkVerifier");

        vm.prank(admin);
        verifier.configureAlgorithm(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            precompile,
            zkVerifier,
            OnChainPQCVerifier.OnChainMode.PRECOMPILE_PREFERRED
        );

        (uint256 total, , , ) = verifier.getAlgorithmStats(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );
        assertEq(total, 0);
    }

    function test_RevertNonAdminConfigure() public {
        vm.prank(user1);
        vm.expectRevert();
        verifier.configureAlgorithm(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            address(0),
            address(0),
            OnChainPQCVerifier.OnChainMode.ZK_PROOF_ONLY
        );
    }

    function test_AdvanceToShadow() public {
        vm.prank(admin);
        verifier.advanceToShadow();

        (OnChainPQCVerifier.OracleDeprecationStage stage, , , ) = verifier
            .getDeprecationInfo();
        assertEq(
            uint8(stage),
            uint8(OnChainPQCVerifier.OracleDeprecationStage.SHADOWED)
        );
    }

    function test_AdvanceToDeprecated() public {
        vm.startPrank(admin);
        verifier.advanceToShadow();
        verifier.advanceToDeprecated();
        vm.stopPrank();

        (OnChainPQCVerifier.OracleDeprecationStage stage, , , ) = verifier
            .getDeprecationInfo();
        assertEq(
            uint8(stage),
            uint8(OnChainPQCVerifier.OracleDeprecationStage.DEPRECATED)
        );
    }

    function test_RevertAdvanceSunsetTooEarly() public {
        vm.startPrank(admin);
        verifier.advanceToShadow();
        verifier.advanceToDeprecated();
        vm.expectRevert();
        verifier.advanceToSunset();
        vm.stopPrank();
    }

    function test_AdvanceToSunsetAfterGracePeriod() public {
        vm.startPrank(admin);
        verifier.advanceToShadow();
        verifier.advanceToDeprecated();
        vm.stopPrank();

        vm.warp(block.timestamp + 31 days);

        vm.prank(admin);
        verifier.advanceToSunset();

        (OnChainPQCVerifier.OracleDeprecationStage stage, , , ) = verifier
            .getDeprecationInfo();
        assertEq(
            uint8(stage),
            uint8(OnChainPQCVerifier.OracleDeprecationStage.SUNSET)
        );
    }

    function test_RevertAdvanceShadowFromWrongStage() public {
        vm.startPrank(admin);
        verifier.advanceToShadow();
        vm.expectRevert();
        verifier.advanceToShadow();
        vm.stopPrank();
    }

    function test_GetDeprecationInfo() public view {
        (
            OnChainPQCVerifier.OracleDeprecationStage stage,
            uint256 deprecationStarted,
            uint256 shadowMismatches,
            bool sunsetEligible
        ) = verifier.getDeprecationInfo();

        assertEq(
            uint8(stage),
            uint8(OnChainPQCVerifier.OracleDeprecationStage.ACTIVE)
        );
        assertEq(deprecationStarted, 0);
        assertEq(shadowMismatches, 0);
        assertFalse(sunsetEligible);
    }

    function test_GetAlgorithmStats() public view {
        (
            uint256 total,
            uint256 successRate,
            uint256 precompileRate,
            uint256 zkProofRate
        ) = verifier.getAlgorithmStats(IPQCVerifier.PQCAlgorithm.FN_DSA_512);
        assertEq(total, 0);
        assertEq(successRate, 0);
        assertEq(precompileRate, 0);
        assertEq(zkProofRate, 0);
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        router_pause();
        assertTrue(verifier.paused());
        vm.prank(admin); // unpause requires DEFAULT_ADMIN_ROLE
        verifier.unpause();
        assertFalse(verifier.paused());
    }

    function test_RevertConfigureKEMAlgorithm() public {
        vm.prank(admin);
        vm.expectRevert();
        verifier.configureAlgorithm(
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            address(1),
            address(2),
            OnChainPQCVerifier.OnChainMode.ZK_PROOF_ONLY
        );
    }

    function test_SetHybridPQCVerifier() public {
        address newAddr = makeAddr("newHub");
        vm.prank(admin);
        verifier.setHybridPQCVerifier(newAddr);
        assertEq(verifier.hybridPQCVerifier(), newAddr);
    }

    function test_DisableAlgorithm() public {
        address precompile = makeAddr("precompile");
        address zkVer = makeAddr("zkVer");

        vm.startPrank(admin);
        verifier.configureAlgorithm(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            precompile,
            zkVer,
            OnChainPQCVerifier.OnChainMode.PRECOMPILE_PREFERRED
        );
        verifier.disableAlgorithm(IPQCVerifier.PQCAlgorithm.FN_DSA_512);
        vm.stopPrank();
    }

    function router_pause() internal {
        verifier.pause();
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 3: STARKVerifierRouter
// ═══════════════════════════════════════════════════════════════════════

contract STARKVerifierRouterTest is Test {
    STARKVerifierRouter public router;
    MockSTARKVerifier public mockStark;
    MockClassicalVerifier public mockClassical;

    address admin;
    address operator;
    address user1;

    bytes32 constant DOMAIN_1 = keccak256("BALANCE_PROOF");
    bytes32 constant DOMAIN_2 = keccak256("SHIELDED_POOL");

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        user1 = makeAddr("user1");
        mockStark = new MockSTARKVerifier();
        mockClassical = new MockClassicalVerifier();

        vm.startPrank(admin);
        router = new STARKVerifierRouter(admin);
        router.grantRole(router.OPERATOR_ROLE(), operator);
        router.grantRole(router.MIGRATION_ADMIN_ROLE(), admin);
        router.grantRole(router.PAUSER_ROLE(), admin);
        vm.stopPrank();
    }

    function test_InitialState() public view {
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_RegisterDomain() public {
        vm.prank(admin);
        router.registerDomain(
            DOMAIN_1,
            "Balance proof domain",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.GROTH16
        );

        STARKVerifierRouter.DomainVerifier memory dv = router.getDomainInfo(
            DOMAIN_1
        );
        assertEq(dv.classicalVerifier, address(mockClassical));
        assertEq(
            uint8(dv.migrationState),
            uint8(STARKVerifierRouter.MigrationState.NOT_STARTED)
        );
        assertTrue(dv.active);
    }

    function test_RegisterSTARKVerifier() public {
        _setupDomain(DOMAIN_1);

        vm.prank(admin);
        router.registerSTARKVerifier(DOMAIN_1, address(mockStark), 90 days);

        STARKVerifierRouter.DomainVerifier memory dv = router.getDomainInfo(
            DOMAIN_1
        );
        assertEq(dv.starkVerifier, address(mockStark));
        assertEq(
            uint8(dv.migrationState),
            uint8(STARKVerifierRouter.MigrationState.PARALLEL)
        );
    }

    function test_RevertRegisterSTARKWithoutDomain() public {
        vm.prank(admin);
        vm.expectRevert();
        router.registerSTARKVerifier(DOMAIN_1, address(mockStark), 90 days);
    }

    function test_AdvanceMigration() public {
        _setupDomainWithSTARK(DOMAIN_1);

        vm.prank(admin);
        router.advanceToSTARKPrimary(DOMAIN_1);

        STARKVerifierRouter.DomainVerifier memory dv = router.getDomainInfo(
            DOMAIN_1
        );
        assertEq(
            uint8(dv.migrationState),
            uint8(STARKVerifierRouter.MigrationState.STARK_PRIMARY)
        );
    }

    function test_FullMigration() public {
        _setupDomainWithSTARK(DOMAIN_1);

        vm.startPrank(admin);
        router.advanceToSTARKPrimary(DOMAIN_1);
        router.advanceToSTARKOnly(DOMAIN_1);
        vm.stopPrank();

        vm.warp(block.timestamp + 91 days);

        vm.prank(admin);
        router.completeMigration(DOMAIN_1);

        STARKVerifierRouter.DomainVerifier memory dv = router.getDomainInfo(
            DOMAIN_1
        );
        assertEq(
            uint8(dv.migrationState),
            uint8(STARKVerifierRouter.MigrationState.COMPLETE)
        );
    }

    function test_RevertCompleteMigrationTooEarly() public {
        _setupDomainWithSTARK(DOMAIN_1);

        vm.startPrank(admin);
        router.advanceToSTARKPrimary(DOMAIN_1);
        router.advanceToSTARKOnly(DOMAIN_1);
        vm.expectRevert();
        router.completeMigration(DOMAIN_1);
        vm.stopPrank();
    }

    function test_ValidateSTARKStructure() public view {
        STARKVerifierRouter.STARKProof memory proof;
        proof.friCommitments = new bytes32[](4);
        for (uint256 i; i < 4; i++) proof.friCommitments[i] = bytes32(i + 1);
        proof.constraintPolyHash = keccak256("constraint");
        proof.traceCommitment = keccak256("trace");
        proof.compositionRoot = keccak256("comp");
        proof.evaluationPoints = new uint256[](2);
        proof.evaluationPoints[0] = 1;
        proof.evaluationPoints[1] = 2;
        proof.decommitmentPaths = new bytes32[](2);
        proof.decommitmentPaths[0] = keccak256("d1");
        proof.decommitmentPaths[1] = keccak256("d2");
        proof.numFriLayers = 4;
        proof.blowupFactor = 8;
        proof.fieldPrime = 0xFFFFFFFF00000001; // Goldilocks

        (bool valid, ) = router.validateSTARKStructure(proof);
        assertTrue(valid);
    }

    function test_ValidateSTARKStructureInvalid() public view {
        STARKVerifierRouter.STARKProof memory proof;
        proof.numFriLayers = 0;
        proof.blowupFactor = 0;
        proof.friCommitments = new bytes32[](0);

        (bool valid, ) = router.validateSTARKStructure(proof);
        assertFalse(valid);
    }

    function test_GetMigrationProgress() public {
        _setupDomainWithSTARK(DOMAIN_1);

        (
            uint256 totalDomains,
            uint256 migrated,
            uint256 inProgress,
            uint256 notStarted,

        ) = router.getMigrationProgress();
        assertEq(totalDomains, 1);
        assertEq(migrated, 0);
        assertEq(inProgress, 1);
        assertEq(notStarted, 0);
    }

    function test_MultipleDomains() public {
        vm.startPrank(admin);
        router.registerDomain(
            DOMAIN_1,
            "Balance proof",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.GROTH16
        );
        router.registerDomain(
            DOMAIN_2,
            "Shielded pool",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.PLONK
        );
        vm.stopPrank();

        (uint256 totalDomains, , , uint256 notStarted, ) = router
            .getMigrationProgress();
        assertEq(totalDomains, 2);
        assertEq(notStarted, 2);
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        router.pause();
        assertTrue(router.paused());
        vm.prank(admin); // unpause requires DEFAULT_ADMIN_ROLE
        router.unpause();
        assertFalse(router.paused());
    }

    function test_GetDomainStats() public {
        _setupDomain(DOMAIN_1);

        (
            uint256 classicalProofs,
            uint256 starkProofs,
            uint256 mismatches,

        ) = router.getDomainStats(DOMAIN_1);
        assertEq(classicalProofs, 0);
        assertEq(starkProofs, 0);
        assertEq(mismatches, 0);
    }

    function test_GetAllDomains() public {
        _setupDomain(DOMAIN_1);
        _setupDomain(DOMAIN_2);

        bytes32[] memory domains = router.getAllDomains();
        assertEq(domains.length, 2);
    }

    function testFuzz_RegisterDomainId(bytes32 domainId) public {
        vm.assume(domainId != bytes32(0));
        vm.prank(admin);
        router.registerDomain(
            domainId,
            "Fuzz domain",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.GROTH16
        );
        STARKVerifierRouter.DomainVerifier memory dv = router.getDomainInfo(
            domainId
        );
        assertEq(dv.classicalVerifier, address(mockClassical));
    }

    function test_RevertDuplicateDomain() public {
        _setupDomain(DOMAIN_1);
        vm.prank(admin);
        vm.expectRevert();
        router.registerDomain(
            DOMAIN_1,
            "Duplicate",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.GROTH16
        );
    }

    function _setupDomain(bytes32 domainId) internal {
        vm.prank(admin);
        router.registerDomain(
            domainId,
            "Test domain",
            address(mockClassical),
            STARKVerifierRouter.ProofSystem.GROTH16
        );
    }

    function _setupDomainWithSTARK(bytes32 domainId) internal {
        _setupDomain(domainId);
        vm.prank(admin);
        router.registerSTARKVerifier(domainId, address(mockStark), 90 days);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 4: PoseidonCommitmentManager
// ═══════════════════════════════════════════════════════════════════════

contract PoseidonCommitmentManagerTest is Test {
    PoseidonCommitmentManager public manager;
    MockPedersenVerifier public mockPedersen;
    MockPoseidonVerifier public mockPoseidon;

    address admin;
    address operator;

    bytes32 constant CIRCUIT_1 = keccak256("balance_proof");
    bytes32 constant CIRCUIT_2 = keccak256("shielded_transfer");

    function setUp() public {
        admin = makeAddr("admin");
        operator = makeAddr("operator");
        mockPedersen = new MockPedersenVerifier();
        mockPoseidon = new MockPoseidonVerifier();

        vm.startPrank(admin);
        manager = new PoseidonCommitmentManager(admin);
        manager.grantRole(manager.OPERATOR_ROLE(), operator);
        manager.grantRole(manager.MIGRATION_ADMIN_ROLE(), admin);
        manager.grantRole(manager.PAUSER_ROLE(), admin);
        vm.stopPrank();
    }

    function test_RegisterCircuit() public {
        vm.prank(admin);
        manager.registerCircuit(
            CIRCUIT_1,
            "Balance proof circuit",
            address(mockPedersen)
        );

        PoseidonCommitmentManager.CircuitConfig memory cfg = manager
            .getCircuitInfo(CIRCUIT_1);
        assertEq(cfg.pedersenVerifier, address(mockPedersen));
        assertEq(
            uint8(cfg.state),
            uint8(PoseidonCommitmentManager.CircuitMigrationState.PEDERSEN_ONLY)
        );
        assertTrue(cfg.active);
    }

    function test_RegisterPoseidonVerifier() public {
        _setupCircuit(CIRCUIT_1);

        vm.prank(admin);
        manager.registerPoseidonVerifier(
            CIRCUIT_1,
            address(mockPoseidon),
            60 days
        );

        PoseidonCommitmentManager.CircuitConfig memory cfg = manager
            .getCircuitInfo(CIRCUIT_1);
        assertEq(cfg.poseidonVerifier, address(mockPoseidon));
        assertEq(
            uint8(cfg.state),
            uint8(
                PoseidonCommitmentManager.CircuitMigrationState.DUAL_ACCEPTANCE
            )
        );
    }

    function test_AdvanceToComplete() public {
        _setupCircuitDual(CIRCUIT_1);

        vm.startPrank(admin);
        manager.advanceToPoseidonPrimary(CIRCUIT_1);
        manager.advanceToPoseidonOnly(CIRCUIT_1);
        vm.stopPrank();

        vm.warp(block.timestamp + 61 days);

        vm.prank(admin);
        manager.completeMigration(CIRCUIT_1);

        PoseidonCommitmentManager.CircuitConfig memory cfg = manager
            .getCircuitInfo(CIRCUIT_1);
        assertEq(
            uint8(cfg.state),
            uint8(PoseidonCommitmentManager.CircuitMigrationState.COMPLETE)
        );
    }

    function test_RevertCompleteBeforeSunset() public {
        _setupCircuitDual(CIRCUIT_1);

        vm.startPrank(admin);
        manager.advanceToPoseidonPrimary(CIRCUIT_1);
        manager.advanceToPoseidonOnly(CIRCUIT_1);
        vm.expectRevert();
        manager.completeMigration(CIRCUIT_1);
        vm.stopPrank();
    }

    function test_GetMigrationReport() public {
        _setupCircuitDual(CIRCUIT_1);

        vm.prank(admin);
        manager.registerCircuit(
            CIRCUIT_2,
            "Shielded transfer",
            address(mockPedersen)
        );

        PoseidonCommitmentManager.MigrationReport memory report = manager
            .getMigrationReport();
        assertEq(report.totalCircuits, 2);
        assertEq(report.inDualMode, 1);
        assertEq(report.notStarted, 1);
    }

    function test_BatchAdvance() public {
        vm.startPrank(admin);
        manager.registerCircuit(CIRCUIT_1, "C1", address(mockPedersen));
        manager.registerPoseidonVerifier(
            CIRCUIT_1,
            address(mockPoseidon),
            60 days
        );
        manager.registerCircuit(CIRCUIT_2, "C2", address(mockPedersen));
        manager.registerPoseidonVerifier(
            CIRCUIT_2,
            address(mockPoseidon),
            60 days
        );
        vm.stopPrank();

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = CIRCUIT_1;
        ids[1] = CIRCUIT_2;

        vm.prank(admin);
        manager.batchAdvance(
            ids,
            PoseidonCommitmentManager.CircuitMigrationState.POSEIDON_PRIMARY
        );

        PoseidonCommitmentManager.CircuitConfig memory cfg1 = manager
            .getCircuitInfo(CIRCUIT_1);
        PoseidonCommitmentManager.CircuitConfig memory cfg2 = manager
            .getCircuitInfo(CIRCUIT_2);
        assertEq(
            uint8(cfg1.state),
            uint8(
                PoseidonCommitmentManager.CircuitMigrationState.POSEIDON_PRIMARY
            )
        );
        assertEq(
            uint8(cfg2.state),
            uint8(
                PoseidonCommitmentManager.CircuitMigrationState.POSEIDON_PRIMARY
            )
        );
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        manager.pause();
        assertTrue(manager.paused());
        vm.prank(admin); // unpause requires DEFAULT_ADMIN_ROLE
        manager.unpause();
        assertFalse(manager.paused());
    }

    function test_GetAllCircuitIds() public {
        _setupCircuit(CIRCUIT_1);
        _setupCircuit(CIRCUIT_2);

        bytes32[] memory ids = manager.getAllCircuitIds();
        assertEq(ids.length, 2);
    }

    function test_RevertDuplicateCircuit() public {
        _setupCircuit(CIRCUIT_1);
        vm.prank(admin);
        vm.expectRevert();
        manager.registerCircuit(CIRCUIT_1, "Dup", address(mockPedersen));
    }

    function testFuzz_RegisterCircuitId(bytes32 circuitId) public {
        vm.assume(circuitId != bytes32(0));
        vm.prank(admin);
        manager.registerCircuit(
            circuitId,
            "Fuzz circuit",
            address(mockPedersen)
        );
        PoseidonCommitmentManager.CircuitConfig memory cfg = manager
            .getCircuitInfo(circuitId);
        assertEq(cfg.pedersenVerifier, address(mockPedersen));
    }

    function _setupCircuit(bytes32 circuitId) internal {
        vm.prank(admin);
        manager.registerCircuit(
            circuitId,
            "Test circuit",
            address(mockPedersen)
        );
    }

    function _setupCircuitDual(bytes32 circuitId) internal {
        _setupCircuit(circuitId);
        vm.prank(admin);
        manager.registerPoseidonVerifier(
            circuitId,
            address(mockPoseidon),
            60 days
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 5: PQCGraduationManager
// ═══════════════════════════════════════════════════════════════════════

contract PQCGraduationManagerTest is Test {
    PQCGraduationManager public manager;
    MockFeatureRegistry public registry;
    MockHybridPQCVerifier public mockVerifier;

    address admin;
    address attestor;
    address auditor;
    address user1;

    function setUp() public {
        admin = makeAddr("admin");
        attestor = makeAddr("attestor");
        auditor = makeAddr("auditor");
        user1 = makeAddr("user1");
        registry = new MockFeatureRegistry();
        mockVerifier = new MockHybridPQCVerifier();

        vm.startPrank(admin);
        manager = new PQCGraduationManager(
            admin,
            address(registry),
            address(mockVerifier)
        );
        manager.grantRole(manager.GRADUATION_ADMIN_ROLE(), admin);
        manager.grantRole(manager.ATTESTOR_ROLE(), attestor);
        manager.grantRole(manager.AUDITOR_ROLE(), auditor);
        vm.stopPrank();
    }

    function test_InitialState() public view {
        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.DISABLED)
        );
        (bool ready, , ) = manager.isGraduationReady();
        assertFalse(ready);
    }

    function test_SubmitAttestation() public {
        vm.prank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("test_report_v1"),
            "Phase 1 test suite passing"
        );

        assertEq(manager.totalAttestations(), 1);
    }

    function test_RevertNonAttestorSubmit() public {
        vm.prank(user1);
        vm.expectRevert();
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("test"),
            "test"
        );
    }

    function test_GraduateToExperimental() public {
        _submitExperimentalCriteria();

        vm.prank(admin);
        manager.graduateToExperimental();

        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.EXPERIMENTAL)
        );
        assertEq(manager.totalGraduations(), 1);
    }

    function test_RevertGraduateWithoutCriteria() public {
        vm.prank(admin);
        vm.expectRevert();
        manager.graduateToExperimental();
    }

    function test_GraduateToBeta() public {
        _graduateToExperimental();

        // Submit BETA criteria
        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("phase2_tests"),
            "Phase 2 tests passing"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.SHADOW_MODE_CLEAN,
            keccak256("shadow_clean"),
            "No oracle mismatches"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.PEER_REVIEW,
            keccak256("peer_review"),
            "Peer review completed"
        );
        vm.stopPrank();

        // Wait 30 days
        vm.warp(block.timestamp + 31 days);

        vm.prank(admin);
        manager.graduateToBeta();

        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.BETA)
        );
        assertEq(manager.totalGraduations(), 2);
    }

    function test_RevertGraduateBetaTooEarly() public {
        _graduateToExperimental();

        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("t"),
            "t"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.SHADOW_MODE_CLEAN,
            keccak256("s"),
            "s"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.PEER_REVIEW,
            keccak256("p"),
            "p"
        );
        vm.stopPrank();

        vm.prank(admin);
        vm.expectRevert();
        manager.graduateToBeta();
    }

    function test_GraduateToProduction() public {
        _graduateToBeta();

        // Submit PRODUCTION criteria
        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("full_tests"),
            "Full test suite >99%"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.INCIDENT_FREE,
            keccak256("incident_free"),
            "Zero critical incidents"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.ON_CHAIN_VERIFICATION,
            keccak256("on_chain"),
            "On-chain verification operational"
        );
        vm.stopPrank();

        vm.prank(auditor);
        manager.submitAuditAttestation(
            keccak256("audit_report_hash"),
            "SecurityFirm Inc."
        );

        // Wait 90 days
        vm.warp(block.timestamp + 91 days);

        vm.prank(admin);
        manager.graduateToProduction();

        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.PRODUCTION)
        );
        assertEq(manager.totalGraduations(), 3);
    }

    function test_HaltGraduation() public {
        _submitExperimentalCriteria();

        vm.prank(admin);
        manager.haltGraduation("Critical vulnerability found");

        assertTrue(manager.graduationHalted());

        vm.prank(admin);
        vm.expectRevert();
        manager.graduateToExperimental();
    }

    function test_ResumeGraduation() public {
        vm.startPrank(admin);
        manager.haltGraduation("Test halt");
        manager.resumeGraduation();
        vm.stopPrank();

        assertFalse(manager.graduationHalted());
    }

    function test_GetGraduationSummary() public view {
        (
            PQCGraduationManager.FeatureStatus status,
            ,
            uint256 totalGrads,
            uint256 totalAtts,
            bool halted
        ) = manager.getGraduationSummary();

        assertEq(
            uint8(status),
            uint8(PQCGraduationManager.FeatureStatus.DISABLED)
        );
        assertEq(totalGrads, 0);
        assertEq(totalAtts, 0);
        assertFalse(halted);
    }

    function test_IsGraduationReadyForExperimental() public {
        _submitExperimentalCriteria();

        (bool ready, uint256 met, uint256 required) = manager
            .isGraduationReady();
        assertTrue(ready);
        assertEq(met, 1);
        assertEq(required, 1);
    }

    function test_SetOnChainPQCVerifier() public {
        address newAddr = makeAddr("onChainVerifier");
        vm.prank(admin);
        manager.setOnChainPQCVerifier(newAddr);
        assertEq(manager.onChainPQCVerifier(), newAddr);
    }

    function test_RevertSetZeroOnChainVerifier() public {
        vm.prank(admin);
        vm.expectRevert();
        manager.setOnChainPQCVerifier(address(0));
    }

    function test_SubmitAuditAttestation() public {
        vm.prank(auditor);
        manager.submitAuditAttestation(keccak256("audit"), "AuditFirm");

        assertEq(manager.totalAttestations(), 1);
    }

    function test_GetAttestation() public {
        vm.prank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("evidence"),
            "Test attestation"
        );

        // Verify attestation was recorded by checking total count
        assertEq(manager.totalAttestations(), 1);

        // Attestations are stored under the NEXT status (EXPERIMENTAL when current is DISABLED)
        assertTrue(
            manager.criteriaStatus(
                PQCGraduationManager.FeatureStatus.EXPERIMENTAL,
                PQCGraduationManager.AttestationType.TEST_SUITE_PASSING
            )
        );
    }

    function test_FullLifecycle() public {
        // Step 1: DISABLED -> EXPERIMENTAL
        _graduateToExperimental();
        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.EXPERIMENTAL)
        );

        // Step 2: EXPERIMENTAL -> BETA (don't call _graduateToBeta which re-graduates)
        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("lc_bt1"),
            "bt"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.SHADOW_MODE_CLEAN,
            keccak256("lc_bt2"),
            "bt"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.PEER_REVIEW,
            keccak256("lc_bt3"),
            "bt"
        );
        vm.stopPrank();
        vm.warp(block.timestamp + 31 days);
        vm.prank(admin);
        manager.graduateToBeta();
        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.BETA)
        );

        // Step 3: BETA -> PRODUCTION
        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("ft"),
            "ft"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.INCIDENT_FREE,
            keccak256("if"),
            "if"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.ON_CHAIN_VERIFICATION,
            keccak256("oc"),
            "oc"
        );
        vm.stopPrank();

        vm.prank(auditor);
        manager.submitAuditAttestation(keccak256("audit"), "Auditor");

        vm.warp(block.timestamp + 91 days);
        vm.prank(admin);
        manager.graduateToProduction();

        assertEq(
            uint8(manager.currentStatus()),
            uint8(PQCGraduationManager.FeatureStatus.PRODUCTION)
        );
        assertEq(manager.totalGraduations(), 3);
    }

    function testFuzz_SubmitMultipleAttestations(uint8 count) public {
        vm.assume(count > 0 && count <= 20);

        for (uint8 i = 0; i < count; i++) {
            vm.prank(attestor);
            manager.submitAttestation(
                PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
                keccak256(abi.encodePacked("evidence_", i)),
                "Fuzz attestation"
            );
        }

        assertEq(manager.totalAttestations(), count);
    }

    // ── Helpers ──

    function _submitExperimentalCriteria() internal {
        vm.prank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("tests"),
            "Tests passing"
        );
    }

    function _graduateToExperimental() internal {
        _submitExperimentalCriteria();
        vm.prank(admin);
        manager.graduateToExperimental();
    }

    function _graduateToBeta() internal {
        _graduateToExperimental();

        vm.startPrank(attestor);
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.TEST_SUITE_PASSING,
            keccak256("bt1"),
            "bt"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.SHADOW_MODE_CLEAN,
            keccak256("bt2"),
            "bt"
        );
        manager.submitAttestation(
            PQCGraduationManager.AttestationType.PEER_REVIEW,
            keccak256("bt3"),
            "bt"
        );
        vm.stopPrank();

        vm.warp(block.timestamp + 31 days);
        vm.prank(admin);
        manager.graduateToBeta();
    }
}

// ═══════════════════════════════════════════════════════════════════════
//             TEST SUITE 6: PQCNativeStealth
// ═══════════════════════════════════════════════════════════════════════

contract PQCNativeStealthTest is Test {
    PQCNativeStealth public stealth;
    MockHybridPQCVerifier public mockVerifier;
    MockFalconZKVerifier public mockFalcon;
    MockLegacyPQCStealth public mockLegacy;

    address admin;
    address user1;
    address user2;
    address sender1;

    function setUp() public {
        admin = makeAddr("admin");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        sender1 = makeAddr("sender1");
        mockVerifier = new MockHybridPQCVerifier();
        mockFalcon = new MockFalconZKVerifier();
        mockLegacy = new MockLegacyPQCStealth();

        vm.startPrank(admin);
        stealth = new PQCNativeStealth(
            admin,
            address(mockVerifier),
            address(mockFalcon)
        );
        stealth.grantRole(stealth.PAUSER_ROLE(), admin);
        stealth.setLegacyPQCStealth(address(mockLegacy));
        vm.stopPrank();
    }

    function test_InitialState() public view {
        assertEq(stealth.hybridPQCVerifier(), address(mockVerifier));
        assertEq(stealth.falconZKVerifier(), address(mockFalcon));
        (uint256 meta, uint256 st, uint256 cl, uint256 cc) = stealth.getStats();
        assertEq(meta, 0);
        assertEq(st, 0);
        assertEq(cl, 0);
        assertEq(cc, 0);
    }

    function test_RegisterNativeMetaAddress() public {
        bytes memory spendKey = _genBytes(897); // Falcon-512
        bytes memory viewKey = _genBytes(1184); // ML-KEM-768

        vm.prank(user1);
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );

        (
            ,
            ,
            PQCNativeStealth.SpendAlgorithm spendAlgo,
            PQCNativeStealth.KEMVariant kemVariant,
            ,
            uint256 stealthCount,
            bool active
        ) = stealth.metaAddresses(user1);

        assertTrue(active);
        assertEq(
            uint8(spendAlgo),
            uint8(PQCNativeStealth.SpendAlgorithm.FALCON_512)
        );
        assertEq(
            uint8(kemVariant),
            uint8(PQCNativeStealth.KEMVariant.ML_KEM_768)
        );
        assertEq(stealthCount, 0);
    }

    function test_RevertDuplicateMetaAddress() public {
        _registerMeta(user1);

        bytes memory spendKey = _genBytes(897);
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user1);
        vm.expectRevert();
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertInvalidSpendKeySize() public {
        bytes memory spendKey = _genBytes(100); // Wrong
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user1);
        vm.expectRevert();
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );
    }

    function test_RevertInvalidViewKeySize() public {
        bytes memory spendKey = _genBytes(897);
        bytes memory viewKey = _genBytes(100); // Wrong

        vm.prank(user1);
        vm.expectRevert();
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );
    }

    function test_RevokeMetaAddress() public {
        _registerMeta(user1);

        vm.prank(user1);
        stealth.revokeMetaAddress();

        (, , , , , , bool active) = stealth.metaAddresses(user1);
        assertFalse(active);
    }

    function test_CreateStealthAddress() public {
        _registerMeta(user1);

        bytes memory ct = _genBytes(1088); // ML-KEM-768 ciphertext
        address stealthAddr = makeAddr("stealth1");

        vm.prank(sender1);
        stealth.createStealthAddress(user1, ct, stealthAddr, bytes1(0xAB), 0);

        PQCNativeStealth.StealthRecord memory record = stealth.getStealthRecord(
            stealthAddr
        );
        assertEq(record.stealthAddress, stealthAddr);
        assertEq(record.recipient, user1);
        assertEq(record.nonce, 0);
        assertEq(
            uint8(record.state),
            uint8(PQCNativeStealth.StealthState.ACTIVE)
        );
    }

    function test_RevertCreateStealthInvalidCT() public {
        _registerMeta(user1);

        bytes memory ct = _genBytes(100); // Wrong size
        address stealthAddr = makeAddr("stealth2");

        vm.prank(sender1);
        vm.expectRevert();
        stealth.createStealthAddress(user1, ct, stealthAddr, bytes1(0xAB), 0);
    }

    function test_RevertCiphertextReuse() public {
        _registerMeta(user1);

        bytes memory ct = _genBytes(1088);
        address stealthAddr1 = makeAddr("stealth_a");
        address stealthAddr2 = makeAddr("stealth_b");

        vm.prank(sender1);
        stealth.createStealthAddress(user1, ct, stealthAddr1, bytes1(0xAB), 0);

        vm.prank(sender1);
        vm.expectRevert();
        stealth.createStealthAddress(user1, ct, stealthAddr2, bytes1(0xCD), 1);
    }

    function test_RevertInvalidNonce() public {
        _registerMeta(user1);

        bytes memory ct = _genBytes(1088);
        address stealthAddr = makeAddr("stealth_n");

        vm.prank(sender1);
        vm.expectRevert();
        stealth.createStealthAddress(user1, ct, stealthAddr, bytes1(0xAB), 5);
    }

    function test_ClaimStealthAddress() public {
        _registerMeta(user1);
        address stealthAddr = _createStealth(user1, 0);

        // Pre-approve the ownership proof in mock falcon verifier
        PQCNativeStealth.StealthRecord memory rec = stealth.getStealthRecord(
            stealthAddr
        );
        bytes32 expectedHash = keccak256(
            abi.encodePacked(
                stealth.PQC_NATIVE_DOMAIN(),
                "ownership_proof",
                stealthAddr,
                rec.spendKeyHash,
                rec.ciphertextHash
            )
        );
        mockFalcon.setVerified(expectedHash, true);

        bytes memory proof = _genBytes(256);

        vm.prank(user1);
        stealth.claimStealthAddress(stealthAddr, proof);

        PQCNativeStealth.OwnershipClaim memory claim = stealth
            .getOwnershipClaim(stealthAddr);
        assertEq(claim.claimant, user1);
        assertTrue(claim.verified);

        PQCNativeStealth.StealthRecord memory record = stealth.getStealthRecord(
            stealthAddr
        );
        assertEq(
            uint8(record.state),
            uint8(PQCNativeStealth.StealthState.CLAIMED)
        );
    }

    function test_ClaimUnverifiedStaysActive() public {
        _registerMeta(user1);
        address stealthAddr = _createStealth(user1, 0);

        // Don't pre-approve — verification will fail
        bytes memory proof = _genBytes(256);

        vm.prank(user1);
        stealth.claimStealthAddress(stealthAddr, proof);

        PQCNativeStealth.OwnershipClaim memory claim = stealth
            .getOwnershipClaim(stealthAddr);
        assertFalse(claim.verified);

        PQCNativeStealth.StealthRecord memory record = stealth.getStealthRecord(
            stealthAddr
        );
        assertEq(
            uint8(record.state),
            uint8(PQCNativeStealth.StealthState.ACTIVE)
        );
    }

    function test_RevertClaimNonexistent() public {
        bytes memory proof = _genBytes(256);
        vm.prank(user1);
        vm.expectRevert();
        stealth.claimStealthAddress(makeAddr("nonexistent"), proof);
    }

    function test_RevertClaimTooSmallProof() public {
        _registerMeta(user1);
        address stealthAddr = _createStealth(user1, 0);

        bytes memory proof = _genBytes(64); // < MIN_OWNERSHIP_PROOF_SIZE(128)

        vm.prank(user1);
        vm.expectRevert();
        stealth.claimStealthAddress(stealthAddr, proof);
    }

    function test_RegisterCrossChainTransfer() public {
        _registerMeta(user1);
        address srcStealth = _createStealth(user1, 0);
        address destStealth = makeAddr("dest_stealth");

        bytes32 derivHash = keccak256(
            abi.encodePacked(
                stealth.PQC_NATIVE_DOMAIN(),
                "cross_chain_derivation",
                srcStealth,
                destStealth,
                block.chainid,
                uint256(42161)
            )
        );
        mockFalcon.setVerified(derivHash, true);

        bytes memory proof = _genBytes(256);

        vm.prank(user1);
        stealth.registerCrossChainTransfer(
            srcStealth,
            destStealth,
            42161, // Arbitrum
            proof
        );

        assertEq(stealth.totalCrossChainTransfers(), 1);
    }

    function test_RevertCrossChainSameChain() public {
        _registerMeta(user1);
        address srcStealth = _createStealth(user1, 0);

        bytes memory proof = _genBytes(256);

        vm.prank(user1);
        vm.expectRevert();
        stealth.registerCrossChainTransfer(
            srcStealth,
            makeAddr("dest"),
            block.chainid,
            proof
        );
    }

    function test_MigrateFromLegacy() public {
        mockLegacy.setMeta(
            user2,
            keccak256("old_spend"),
            keccak256("old_view"),
            true
        );

        bytes memory spendKey = _genBytes(897);
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user2);
        stealth.migrateFromLegacy(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );

        (, , , , , , bool active) = stealth.metaAddresses(user2);
        assertTrue(active);
    }

    function test_RevertMigrateInactiveLegacy() public {
        mockLegacy.setMeta(user2, keccak256("s"), keccak256("v"), false);

        bytes memory spendKey = _genBytes(897);
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user2);
        vm.expectRevert();
        stealth.migrateFromLegacy(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );
    }

    function test_ViewTagIndex() public {
        _registerMeta(user1);

        bytes memory ct1 = _genBytes(1088);
        address stealth1 = makeAddr("s1");
        vm.prank(sender1);
        stealth.createStealthAddress(user1, ct1, stealth1, bytes1(0xAA), 0);

        bytes memory ct2 = new bytes(1088);
        ct2[0] = 0xFF;
        for (uint256 i = 1; i < 1088; i++) ct2[i] = bytes1(uint8(i % 256));
        address stealth2 = makeAddr("s2");
        vm.prank(sender1);
        stealth.createStealthAddress(user1, ct2, stealth2, bytes1(0xAA), 1);

        address[] memory results = stealth.getByViewTag(bytes1(0xAA));
        assertEq(results.length, 2);
    }

    function test_DifferentKEMVariants() public {
        bytes memory spend512 = _genBytes(897);
        bytes memory view512 = _genBytes(800); // ML-KEM-512 pk size

        vm.prank(user1);
        stealth.registerNativeMetaAddress(
            spend512,
            view512,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_512
        );

        (, , , PQCNativeStealth.KEMVariant variant, , , ) = stealth
            .metaAddresses(user1);
        assertEq(uint8(variant), uint8(PQCNativeStealth.KEMVariant.ML_KEM_512));
    }

    function test_DifferentSpendAlgorithms() public {
        bytes memory spendKey = _genBytes(1952); // ML-DSA-65
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user1);
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.ML_DSA_65,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );

        (, , PQCNativeStealth.SpendAlgorithm algo, , , , ) = stealth
            .metaAddresses(user1);
        assertEq(uint8(algo), uint8(PQCNativeStealth.SpendAlgorithm.ML_DSA_65));
    }

    function test_AdminSetters() public {
        address newHybrid = makeAddr("newHybrid");
        address newFalcon = makeAddr("newFalcon");
        address newRouter = makeAddr("newRouter");

        vm.startPrank(admin);
        stealth.setHybridPQCVerifier(newHybrid);
        stealth.setFalconZKVerifier(newFalcon);
        stealth.setPQCPrecompileRouter(newRouter);
        vm.stopPrank();

        assertEq(stealth.hybridPQCVerifier(), newHybrid);
        assertEq(stealth.falconZKVerifier(), newFalcon);
        assertEq(stealth.pqcPrecompileRouter(), newRouter);
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        stealth.pause();
        assertTrue(stealth.paused());
        vm.prank(admin); // unpause requires PAUSER_ROLE
        stealth.unpause();
        assertFalse(stealth.paused());
    }

    function test_StatsAccumulate() public {
        _registerMeta(user1);
        _createStealth(user1, 0);
        _createStealth(user1, 1);

        (uint256 meta, uint256 st, , ) = stealth.getStats();
        assertEq(meta, 1);
        assertEq(st, 2);
    }

    function testFuzz_RegisterMultipleUsers(uint8 count) public {
        vm.assume(count > 0 && count <= 10);

        for (uint8 i = 0; i < count; i++) {
            address user = address(uint160(0x1000 + i));
            bytes memory spend = _genBytes(897);
            bytes memory view_ = _genBytes(1184);

            vm.prank(user);
            stealth.registerNativeMetaAddress(
                spend,
                view_,
                PQCNativeStealth.SpendAlgorithm.FALCON_512,
                PQCNativeStealth.KEMVariant.ML_KEM_768
            );
        }

        (uint256 meta, , , ) = stealth.getStats();
        assertEq(meta, count);
    }

    // ── Helpers ──

    function _genBytes(uint256 size) internal pure returns (bytes memory) {
        bytes memory data = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            data[i] = bytes1(uint8(i % 256));
        }
        return data;
    }

    function _registerMeta(address user) internal {
        bytes memory spendKey = _genBytes(897);
        bytes memory viewKey = _genBytes(1184);

        vm.prank(user);
        stealth.registerNativeMetaAddress(
            spendKey,
            viewKey,
            PQCNativeStealth.SpendAlgorithm.FALCON_512,
            PQCNativeStealth.KEMVariant.ML_KEM_768
        );
    }

    function _createStealth(
        address recipient,
        uint32 nonce
    ) internal returns (address stealthAddr) {
        stealthAddr = address(
            uint160(uint256(keccak256(abi.encodePacked("stealth", nonce))))
        );

        bytes memory ct = new bytes(1088);
        for (uint256 i = 0; i < 1088; i++) {
            ct[i] = bytes1(uint8((i + uint256(nonce) * 7) % 256));
        }

        vm.prank(sender1);
        stealth.createStealthAddress(
            recipient,
            ct,
            stealthAddr,
            bytes1(uint8(nonce)),
            nonce
        );
    }
}
