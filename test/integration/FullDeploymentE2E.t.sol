// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// Core
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";

// Verifiers
import {VerifierRegistryV2} from "../../contracts/verifiers/VerifierRegistryV2.sol";
import {ZaseonUniversalVerifier} from "../../contracts/verifiers/ZaseonUniversalVerifier.sol";

// Security
import {RelayProofValidator} from "../../contracts/security/RelayProofValidator.sol";
import {RelayCircuitBreaker} from "../../contracts/security/RelayCircuitBreaker.sol";

// Primitives
import {ZKBoundStateLocks} from "../../contracts/primitives/ZKBoundStateLocks.sol";
import {ProofCarryingContainer} from "../../contracts/primitives/ProofCarryingContainer.sol";
import {CrossDomainNullifierAlgebra} from "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";
import {PolicyBoundProofs} from "../../contracts/primitives/PolicyBoundProofs.sol";

// Governance
import {ZaseonToken} from "../../contracts/governance/ZaseonToken.sol";
import {ZaseonGovernor} from "../../contracts/governance/ZaseonGovernor.sol";
import {ZaseonUpgradeTimelock} from "../../contracts/governance/ZaseonUpgradeTimelock.sol";

// OpenZeppelin
import {IVotes} from "@openzeppelin/contracts/governance/utils/IVotes.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IGovernor} from "@openzeppelin/contracts/governance/IGovernor.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title FullDeploymentE2E
 * @notice End-to-end test that mirrors DeployMainnet.s.sol:
 *         deploys real contracts, wires the Hub, configures governance,
 *         and tests the full propose → vote → queue → execute upgrade lifecycle.
 */
contract FullDeploymentE2E is Test {
    // ── Contracts ──
    ZaseonProtocolHub public hub;
    VerifierRegistryV2 public verifierRegistry;
    ZaseonUniversalVerifier public universalVerifier;
    NullifierRegistryV3 public nullifierRegistry;
    RelayProofValidator public relayProofValidator;
    RelayCircuitBreaker public circuitBreaker;
    ZKBoundStateLocks public zkBoundStateLocks;
    ProofCarryingContainer public proofCarryingContainer;
    CrossDomainNullifierAlgebra public cdna;
    PolicyBoundProofs public policyBoundProofs;
    ZaseonToken public zaseonToken;
    ZaseonGovernor public governor;
    ZaseonUpgradeTimelock public upgradeTimelock;

    // ── Actors ──
    address public deployer;
    address public admin = makeAddr("admin");
    address public voter1 = makeAddr("voter1");
    address public voter2 = makeAddr("voter2");
    address public voter3 = makeAddr("voter3");

    function setUp() public {
        deployer = address(this);

        // ════════ PHASE 1: Deploy all contracts ════════
        hub = new ZaseonProtocolHub();
        verifierRegistry = new VerifierRegistryV2();
        universalVerifier = new ZaseonUniversalVerifier();
        nullifierRegistry = new NullifierRegistryV3();
        relayProofValidator = new RelayProofValidator(deployer);
        circuitBreaker = new RelayCircuitBreaker(deployer);
        zkBoundStateLocks = new ZKBoundStateLocks(address(universalVerifier));
        proofCarryingContainer = new ProofCarryingContainer();
        cdna = new CrossDomainNullifierAlgebra();
        policyBoundProofs = new PolicyBoundProofs();

        // ════════ PHASE 2: Governance ════════
        uint256 totalSupply = 10_000_000e18;
        zaseonToken = new ZaseonToken(deployer, deployer, totalSupply);

        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // anyone can execute
        upgradeTimelock = new ZaseonUpgradeTimelock(
            1 days,
            proposers,
            executors,
            admin
        );

        governor = new ZaseonGovernor(
            IVotes(address(zaseonToken)),
            TimelockController(payable(address(upgradeTimelock))),
            0,
            0,
            0,
            0 // defaults
        );

        // Grant governor roles on timelock
        vm.startPrank(admin);
        upgradeTimelock.grantRole(
            upgradeTimelock.PROPOSER_ROLE(),
            address(governor)
        );
        upgradeTimelock.grantRole(
            upgradeTimelock.EXECUTOR_ROLE(),
            address(governor)
        );
        upgradeTimelock.grantRole(
            upgradeTimelock.CANCELLER_ROLE(),
            address(governor)
        );
        vm.stopPrank();

        // Distribute tokens to voters and delegate
        zaseonToken.transfer(voter1, 5_000_000e18);
        zaseonToken.transfer(voter2, 3_000_000e18);
        zaseonToken.transfer(voter3, 2_000_000e18);

        vm.prank(voter1);
        zaseonToken.delegate(voter1);
        vm.prank(voter2);
        zaseonToken.delegate(voter2);
        vm.prank(voter3);
        zaseonToken.delegate(voter3);

        // Advance 1 block for vote snapshotting
        vm.warp(block.timestamp + 1);

        // ════════ PHASE 3: Wire Hub ════════
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(verifierRegistry),
                _universalVerifier: address(universalVerifier),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0),
                _nullifierManager: address(nullifierRegistry),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _relayProofValidator: address(relayProofValidator),
                _zkBoundStateLocks: address(zkBoundStateLocks),
                _proofCarryingContainer: address(proofCarryingContainer),
                _crossDomainNullifierAlgebra: address(cdna),
                _policyBoundProofs: address(policyBoundProofs),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        hub.setTimelock(address(upgradeTimelock));
        hub.setUpgradeTimelock(address(upgradeTimelock));
    }

    // ═══════════════════════════════════════════════════════════
    //                    HUB WIRING TESTS
    // ═══════════════════════════════════════════════════════════

    function test_HubIsWiredCorrectly() public view {
        assertEq(hub.verifierRegistry(), address(verifierRegistry));
        assertEq(hub.universalVerifier(), address(universalVerifier));
        assertEq(hub.nullifierManager(), address(nullifierRegistry));
        assertEq(hub.relayProofValidator(), address(relayProofValidator));
        assertEq(hub.zkBoundStateLocks(), address(zkBoundStateLocks));
        assertEq(hub.proofCarryingContainer(), address(proofCarryingContainer));
        assertEq(hub.crossDomainNullifierAlgebra(), address(cdna));
        assertEq(hub.policyBoundProofs(), address(policyBoundProofs));
        assertEq(hub.timelock(), address(upgradeTimelock));
        assertEq(hub.upgradeTimelock(), address(upgradeTimelock));
    }

    function test_HubIsFullyConfiguredWithCriticalComponents() public {
        // isFullyConfigured now checks 16 components (core privacy, cross-chain, privacy features)
        // We're missing several components, so it should not be fully configured yet
        assertFalse(hub.isFullyConfigured());

        // Wire the missing critical components
        hub.setShieldedPool(address(0xBEEF));
        hub.setPrivacyRouter(address(0xCAFE));
        hub.setCrossChainMessageRelay(address(0xA001));
        hub.setCrossChainPrivacyHub(address(0xA002));
        hub.setStealthAddressRegistry(address(0xA003));
        hub.setPrivateRelayerNetwork(address(0xA004));
        hub.setComplianceOracle(address(0xA005));
        hub.setRelayWatchtower(address(0xA006));
        hub.setMultiProver(address(0xA007));
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0),
                _universalVerifier: address(0),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0xA008)
            })
        );

        assertTrue(hub.isFullyConfigured());
    }

    function test_GetComponentStatusReturns17() public view {
        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();
        assertEq(names.length, 26);
        assertEq(addrs.length, 26);
        // First component is verifierRegistry
        assertEq(addrs[0], address(verifierRegistry));
    }

    function test_HubPauseAndUnpause() public {
        hub.pause();
        assertTrue(hub.paused());
        hub.unpause();
        assertFalse(hub.paused());
    }

    // ═══════════════════════════════════════════════════════════
    //               VERIFIER REGISTRY TESTS
    // ═══════════════════════════════════════════════════════════

    function test_VerifierRegistryDeployed() public view {
        assertEq(verifierRegistry.CIRCUIT_TYPE_COUNT(), 24);
        assertEq(verifierRegistry.totalRegistered(), 0);
        assertFalse(verifierRegistry.paused());
    }

    function test_RegisterAndQueryVerifier() public {
        // Register a mock verifier for STATE_TRANSFER
        address mockVerifier = address(0x1111);
        address mockAdapter = address(0x2222);
        bytes32 circuitHash = keccak256("state_transfer_v1");

        uint256 version = verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            mockVerifier,
            mockAdapter,
            circuitHash
        );

        assertEq(version, 1);
        assertEq(verifierRegistry.totalRegistered(), 1);
        assertTrue(
            verifierRegistry.isActive(
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        assertEq(
            verifierRegistry.getAdapter(
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            ),
            mockAdapter
        );
    }

    function test_VerifierDeprecationAndRollback() public {
        address v1Verifier = address(0x1111);
        address v1Adapter = address(0x2222);
        address v2Verifier = address(0x3333);
        address v2Adapter = address(0x4444);

        // Register v1
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            v1Verifier,
            v1Adapter,
            keccak256("v1")
        );

        // Upgrade to v2
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            v2Verifier,
            v2Adapter,
            keccak256("v2")
        );

        assertEq(
            verifierRegistry.getAdapter(
                VerifierRegistryV2.CircuitType.NULLIFIER
            ),
            v2Adapter
        );

        // Deprecate v2
        verifierRegistry.deprecateVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            "security issue"
        );

        // Emergency rollback to v1
        verifierRegistry.emergencyRollback(
            VerifierRegistryV2.CircuitType.NULLIFIER
        );
        assertEq(
            verifierRegistry.getAdapter(
                VerifierRegistryV2.CircuitType.NULLIFIER
            ),
            v1Adapter
        );
    }

    function test_ProofTypeMappingForHub() public {
        // Register verifier
        address mockAdapter = address(0x5555);
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.CROSS_CHAIN_PROOF,
            address(0x5554),
            mockAdapter,
            keccak256("cc")
        );

        // Map bytes32 proof type to CircuitType
        bytes32 proofType = keccak256("CROSS_CHAIN");
        verifierRegistry.setProofTypeMapping(
            proofType,
            VerifierRegistryV2.CircuitType.CROSS_CHAIN_PROOF
        );

        // Query via getVerifier(bytes32)
        assertEq(verifierRegistry.getVerifier(proofType), mockAdapter);
    }

    // ═══════════════════════════════════════════════════════════
    //              GOVERNANCE UPGRADE E2E LIFECYCLE
    // ═══════════════════════════════════════════════════════════

    function test_GovernanceFullLifecycle() public {
        // Step 1: Create a proposal to call hub.setShieldedPool(newPool)
        address newPool = address(0xBEEF);
        address[] memory targets = new address[](1);
        targets[0] = address(hub);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            hub.setShieldedPool.selector,
            newPool
        );
        string memory description = "Set ShieldedPool address";

        // voter1 proposes (has 5M tokens > 100k threshold)
        vm.prank(voter1);
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );
        assertTrue(proposalId != 0);

        // Step 2: Advance past voting delay (1 day)
        vm.warp(block.timestamp + 1 days + 1);

        // Step 3: Vote — voters 1, 2, 3 all vote FOR
        vm.prank(voter1);
        governor.castVote(proposalId, 1); // For

        vm.prank(voter2);
        governor.castVote(proposalId, 1); // For

        vm.prank(voter3);
        governor.castVote(proposalId, 1); // For

        // Step 4: Advance past voting period (5 days)
        vm.warp(block.timestamp + 5 days + 1);

        // Proposal should be succeeded
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded)
        );

        // Step 5: Queue in timelock
        bytes32 descHash = keccak256(bytes(description));
        governor.queue(targets, values, calldatas, descHash);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Queued)
        );

        // Step 6: Advance past timelock delay (1 day)
        vm.warp(block.timestamp + 1 days + 1);

        // Step 7: Execute
        // Hub must grant OPERATOR_ROLE to the timelock so it can call setShieldedPool
        hub.grantRole(hub.OPERATOR_ROLE(), address(upgradeTimelock));
        governor.execute(targets, values, calldatas, descHash);

        // Step 8: Verify the upgrade took effect
        assertEq(hub.shieldedPool(), newPool);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed)
        );
    }

    function test_GovernanceDefeatedProposal() public {
        address[] memory targets = new address[](1);
        targets[0] = address(hub);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            hub.setShieldedPool.selector,
            address(0xDEAD)
        );
        string memory description = "Bad proposal";

        vm.prank(voter1);
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // Advance past voting delay
        vm.warp(block.timestamp + 1 days + 1);

        // voter1 (5M) votes FOR, voter2 (3M) and voter3 (2M) vote AGAINST
        vm.prank(voter1);
        governor.castVote(proposalId, 1); // For

        vm.prank(voter2);
        governor.castVote(proposalId, 0); // Against

        vm.prank(voter3);
        governor.castVote(proposalId, 0); // Against

        // Advance past voting period
        vm.warp(block.timestamp + 5 days + 1);

        // 5M for vs 5M against — should be defeated (against >= for)
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated)
        );
    }

    function test_GovernanceQuorumNotReached() public {
        // Only voter3 (2M = 20%) votes, need 4% quorum = 400k. But voter3 votes alone.
        // Actually 2M > 400k so quorum is reached. Let's use a smaller voter.
        address smallVoter = makeAddr("smallVoter");
        zaseonToken.mint(smallVoter, 100_000e18);
        vm.prank(smallVoter);
        zaseonToken.delegate(smallVoter);
        vm.warp(block.timestamp + 1);

        address[] memory targets = new address[](1);
        targets[0] = address(hub);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            hub.setShieldedPool.selector,
            address(0xDEAD)
        );
        string memory description = "Low quorum proposal";

        // voter1 proposes
        vm.prank(voter1);
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );
        vm.warp(block.timestamp + 1 days + 1);

        // Only smallVoter (100k) votes — quorum needs 4% of (5M+3M+2M+100k) = ~404k
        vm.prank(smallVoter);
        governor.castVote(proposalId, 1); // For

        vm.warp(block.timestamp + 5 days + 1);

        // Quorum not reached — defeated
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Defeated)
        );
    }

    // ═══════════════════════════════════════════════════════════
    //                  CROSS-CUTTING INTEGRATION
    // ═══════════════════════════════════════════════════════════

    function test_VerifierRegistryPauseBlocksVerification() public {
        // Register a verifier
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.MERKLE_PROOF,
            address(0x111),
            address(0x222),
            keccak256("merkle")
        );

        // Pause the registry
        verifierRegistry.pause();
        assertTrue(verifierRegistry.paused());

        // Verification should revert
        vm.expectRevert(VerifierRegistryV2.RegistryPausedError.selector);
        verifierRegistry.verify(
            VerifierRegistryV2.CircuitType.MERKLE_PROOF,
            hex"dead",
            hex"beef"
        );

        // Unpause
        verifierRegistry.unpause();
        assertFalse(verifierRegistry.paused());
    }

    function test_BatchRegisterVerifiers() public {
        VerifierRegistryV2.CircuitType[]
            memory types = new VerifierRegistryV2.CircuitType[](3);
        types[0] = VerifierRegistryV2.CircuitType.NULLIFIER;
        types[1] = VerifierRegistryV2.CircuitType.MERKLE_PROOF;
        types[2] = VerifierRegistryV2.CircuitType.POLICY;

        address[] memory verifiers = new address[](3);
        verifiers[0] = address(0x100);
        verifiers[1] = address(0x200);
        verifiers[2] = address(0x300);

        address[] memory adapters = new address[](3);
        adapters[0] = address(0x101);
        adapters[1] = address(0x201);
        adapters[2] = address(0x301);

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = keccak256("nullifier");
        hashes[1] = keccak256("merkle");
        hashes[2] = keccak256("policy");

        verifierRegistry.batchRegisterVerifiers(
            types,
            verifiers,
            adapters,
            hashes
        );

        assertEq(verifierRegistry.totalRegistered(), 3);
        assertTrue(
            verifierRegistry.isActive(VerifierRegistryV2.CircuitType.NULLIFIER)
        );
        assertTrue(
            verifierRegistry.isActive(
                VerifierRegistryV2.CircuitType.MERKLE_PROOF
            )
        );
        assertTrue(
            verifierRegistry.isActive(VerifierRegistryV2.CircuitType.POLICY)
        );
    }

    function test_HubEmergencyDeactivateBridge() public {
        // Register a bridge adapter
        hub.registerRelayAdapter(42161, address(0xA0B1), true, 12);

        // Deactivate it
        hub.deactivateRelay(42161);

        // Bridge should show as inactive
        IZaseonProtocolHub.RelayInfo memory info = hub.getRelayInfo(42161);
        assertFalse(info.isActive);
    }

    function test_MultiPhaseWiringPreservesExisting() public {
        // Phase 1: wire primitives
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0),
                _universalVerifier: address(0),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0xBEEF),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0xCAFE),
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        // Verify new values set AND old values preserved
        assertEq(hub.shieldedPool(), address(0xBEEF));
        assertEq(hub.privacyRouter(), address(0xCAFE));
        assertEq(hub.verifierRegistry(), address(verifierRegistry)); // from setUp
        assertEq(hub.zkBoundStateLocks(), address(zkBoundStateLocks)); // from setUp
    }

    function test_ZaseonTokenGovernancePower() public view {
        // Verify voting power delegation
        assertEq(zaseonToken.getVotes(voter1), 5_000_000e18);
        assertEq(zaseonToken.getVotes(voter2), 3_000_000e18);
        assertEq(zaseonToken.getVotes(voter3), 2_000_000e18);
        assertEq(zaseonToken.totalSupply(), 10_000_000e18);
    }

    function test_GovernorConfiguration() public view {
        assertEq(governor.name(), "ZaseonGovernor");
        assertEq(governor.votingDelay(), 1 days);
        assertEq(governor.votingPeriod(), 5 days);
        assertEq(governor.proposalThreshold(), 100_000e18);
        assertEq(governor.timelock(), address(upgradeTimelock));
    }

    // ═══════════════════════════════════════════════════════════
    //        PHASE 7: ROLE TRANSFER TO MULTISIG (ADMIN)
    // ═══════════════════════════════════════════════════════════

    /// @dev Helper: mirrors DeployMainnet Phase 7 — grant all roles to admin
    function _executePhase7_RoleTransfer() internal {
        // ── ZaseonProtocolHub ──
        hub.grantRole(hub.DEFAULT_ADMIN_ROLE(), admin);
        hub.grantRole(hub.OPERATOR_ROLE(), admin);
        hub.grantRole(hub.GUARDIAN_ROLE(), admin);
        hub.grantRole(hub.UPGRADER_ROLE(), admin);

        // ── NullifierRegistryV3 ──
        nullifierRegistry.grantRole(
            nullifierRegistry.DEFAULT_ADMIN_ROLE(),
            admin
        );
        nullifierRegistry.grantRole(nullifierRegistry.REGISTRAR_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.RELAY_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.EMERGENCY_ROLE(), admin);

        // ── VerifierRegistryV2 ──
        verifierRegistry.grantRole(
            verifierRegistry.DEFAULT_ADMIN_ROLE(),
            admin
        );
        verifierRegistry.grantRole(
            verifierRegistry.REGISTRY_ADMIN_ROLE(),
            admin
        );
        verifierRegistry.grantRole(verifierRegistry.GUARDIAN_ROLE(), admin);

        // ── RelayProofValidator ──
        relayProofValidator.grantRole(
            relayProofValidator.DEFAULT_ADMIN_ROLE(),
            admin
        );
        relayProofValidator.grantRole(
            relayProofValidator.GUARDIAN_ROLE(),
            admin
        );
        relayProofValidator.grantRole(
            relayProofValidator.OPERATOR_ROLE(),
            admin
        );
        relayProofValidator.grantRole(
            relayProofValidator.WATCHTOWER_ROLE(),
            admin
        );

        // ── RelayCircuitBreaker ──
        circuitBreaker.grantRole(circuitBreaker.DEFAULT_ADMIN_ROLE(), admin);
        circuitBreaker.grantRole(circuitBreaker.GUARDIAN_ROLE(), admin);
        circuitBreaker.grantRole(circuitBreaker.MONITOR_ROLE(), admin);
        circuitBreaker.grantRole(circuitBreaker.RECOVERY_ROLE(), admin);
    }

    /// @dev Helper: mirrors DeployMainnet Phase 8 — deployer renounces all roles
    function _executePhase8_RenounceDeployer() internal {
        // ── ZaseonProtocolHub ──
        hub.renounceRole(hub.UPGRADER_ROLE(), deployer);
        hub.renounceRole(hub.GUARDIAN_ROLE(), deployer);
        hub.renounceRole(hub.OPERATOR_ROLE(), deployer);
        hub.renounceRole(hub.DEFAULT_ADMIN_ROLE(), deployer);

        // ── NullifierRegistryV3 ──
        nullifierRegistry.renounceRole(
            nullifierRegistry.EMERGENCY_ROLE(),
            deployer
        );
        nullifierRegistry.renounceRole(
            nullifierRegistry.RELAY_ROLE(),
            deployer
        );
        nullifierRegistry.renounceRole(
            nullifierRegistry.REGISTRAR_ROLE(),
            deployer
        );
        nullifierRegistry.renounceRole(
            nullifierRegistry.DEFAULT_ADMIN_ROLE(),
            deployer
        );

        // ── VerifierRegistryV2 ──
        verifierRegistry.renounceRole(
            verifierRegistry.REGISTRY_ADMIN_ROLE(),
            deployer
        );
        verifierRegistry.renounceRole(
            verifierRegistry.GUARDIAN_ROLE(),
            deployer
        );
        verifierRegistry.renounceRole(
            verifierRegistry.DEFAULT_ADMIN_ROLE(),
            deployer
        );

        // ── RelayProofValidator ──
        relayProofValidator.renounceRole(
            relayProofValidator.WATCHTOWER_ROLE(),
            deployer
        );
        relayProofValidator.renounceRole(
            relayProofValidator.OPERATOR_ROLE(),
            deployer
        );
        relayProofValidator.renounceRole(
            relayProofValidator.GUARDIAN_ROLE(),
            deployer
        );
        relayProofValidator.renounceRole(
            relayProofValidator.DEFAULT_ADMIN_ROLE(),
            deployer
        );

        // ── RelayCircuitBreaker ──
        circuitBreaker.renounceRole(circuitBreaker.RECOVERY_ROLE(), deployer);
        circuitBreaker.renounceRole(circuitBreaker.MONITOR_ROLE(), deployer);
        circuitBreaker.renounceRole(circuitBreaker.GUARDIAN_ROLE(), deployer);
        circuitBreaker.renounceRole(
            circuitBreaker.DEFAULT_ADMIN_ROLE(),
            deployer
        );
    }

    function test_Phase7_RoleTransferGrantsAdminAllRoles() public {
        _executePhase7_RoleTransfer();

        // ── Hub ──
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), admin));
        assertTrue(hub.hasRole(hub.GUARDIAN_ROLE(), admin));
        assertTrue(hub.hasRole(hub.UPGRADER_ROLE(), admin));

        // ── NullifierRegistryV3 ──
        assertTrue(
            nullifierRegistry.hasRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.REGISTRAR_ROLE(), admin)
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.RELAY_ROLE(), admin)
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.EMERGENCY_ROLE(), admin)
        );

        // ── VerifierRegistryV2 ──
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            verifierRegistry.hasRole(verifierRegistry.GUARDIAN_ROLE(), admin)
        );

        // ── RelayProofValidator ──
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.GUARDIAN_ROLE(),
                admin
            )
        );
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.OPERATOR_ROLE(),
                admin
            )
        );
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.WATCHTOWER_ROLE(),
                admin
            )
        );

        // ── RelayCircuitBreaker ──
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.GUARDIAN_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.MONITOR_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.RECOVERY_ROLE(), admin)
        );
    }

    function test_Phase7_AdminCanOperateHubAfterTransfer() public {
        _executePhase7_RoleTransfer();

        // Admin can set a new component on the hub
        vm.startPrank(admin);
        hub.setShieldedPool(address(0xDEAD));
        assertEq(hub.shieldedPool(), address(0xDEAD));

        hub.pause();
        assertTrue(hub.paused());
        hub.unpause();
        assertFalse(hub.paused());
        vm.stopPrank();
    }

    function test_Phase7_AdminCanOperateVerifierRegistryAfterTransfer() public {
        _executePhase7_RoleTransfer();

        vm.startPrank(admin);
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            address(0x1111),
            address(0x2222),
            keccak256("nullifier_v1")
        );
        assertEq(verifierRegistry.totalRegistered(), 1);
        assertTrue(
            verifierRegistry.isActive(VerifierRegistryV2.CircuitType.NULLIFIER)
        );
        vm.stopPrank();
    }

    function test_Phase7_AdminCanOperateNullifierRegistryAfterTransfer()
        public
    {
        _executePhase7_RoleTransfer();

        vm.startPrank(admin);
        nullifierRegistry.pause();
        assertTrue(nullifierRegistry.paused());
        nullifierRegistry.unpause();
        assertFalse(nullifierRegistry.paused());
        vm.stopPrank();
    }

    function test_Phase7_DeployerStillHasRolesBeforeRenounce() public {
        _executePhase7_RoleTransfer();

        // Both deployer AND admin should have roles at this point
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), deployer));
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), admin));
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                deployer
            )
        );
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                admin
            )
        );
    }

    // ═══════════════════════════════════════════════════════════
    //        PHASE 8: RENOUNCE DEPLOYER ROLES
    // ═══════════════════════════════════════════════════════════

    function test_Phase8_DeployerHasNoRolesAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // ── Hub: deployer has NO roles ──
        assertFalse(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.OPERATOR_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.GUARDIAN_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.UPGRADER_ROLE(), deployer));

        // ── NullifierRegistryV3: deployer has NO roles ──
        assertFalse(
            nullifierRegistry.hasRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                deployer
            )
        );
        assertFalse(
            nullifierRegistry.hasRole(
                nullifierRegistry.REGISTRAR_ROLE(),
                deployer
            )
        );
        assertFalse(
            nullifierRegistry.hasRole(nullifierRegistry.RELAY_ROLE(), deployer)
        );
        assertFalse(
            nullifierRegistry.hasRole(
                nullifierRegistry.EMERGENCY_ROLE(),
                deployer
            )
        );

        // ── VerifierRegistryV2: deployer has NO roles ──
        assertFalse(
            verifierRegistry.hasRole(
                verifierRegistry.DEFAULT_ADMIN_ROLE(),
                deployer
            )
        );
        assertFalse(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                deployer
            )
        );
        assertFalse(
            verifierRegistry.hasRole(verifierRegistry.GUARDIAN_ROLE(), deployer)
        );

        // ── RelayProofValidator: deployer has NO roles ──
        assertFalse(
            relayProofValidator.hasRole(
                relayProofValidator.DEFAULT_ADMIN_ROLE(),
                deployer
            )
        );
        assertFalse(
            relayProofValidator.hasRole(
                relayProofValidator.OPERATOR_ROLE(),
                deployer
            )
        );
        assertFalse(
            relayProofValidator.hasRole(
                relayProofValidator.GUARDIAN_ROLE(),
                deployer
            )
        );
        assertFalse(
            relayProofValidator.hasRole(
                relayProofValidator.WATCHTOWER_ROLE(),
                deployer
            )
        );

        // ── RelayCircuitBreaker: deployer has NO roles ──
        assertFalse(
            circuitBreaker.hasRole(
                circuitBreaker.DEFAULT_ADMIN_ROLE(),
                deployer
            )
        );
        assertFalse(
            circuitBreaker.hasRole(circuitBreaker.GUARDIAN_ROLE(), deployer)
        );
        assertFalse(
            circuitBreaker.hasRole(circuitBreaker.MONITOR_ROLE(), deployer)
        );
        assertFalse(
            circuitBreaker.hasRole(circuitBreaker.RECOVERY_ROLE(), deployer)
        );
    }

    function test_Phase8_AdminRetainsAllRolesAfterDeployerRenounces() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // ── Hub: admin still has all roles ──
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), admin));
        assertTrue(hub.hasRole(hub.GUARDIAN_ROLE(), admin));
        assertTrue(hub.hasRole(hub.UPGRADER_ROLE(), admin));

        // ── NullifierRegistryV3: admin still has all roles ──
        assertTrue(
            nullifierRegistry.hasRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.REGISTRAR_ROLE(), admin)
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.RELAY_ROLE(), admin)
        );
        assertTrue(
            nullifierRegistry.hasRole(nullifierRegistry.EMERGENCY_ROLE(), admin)
        );

        // ── VerifierRegistryV2: admin still has all roles ──
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            verifierRegistry.hasRole(verifierRegistry.GUARDIAN_ROLE(), admin)
        );

        // ── RelayProofValidator: admin still has all roles ──
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.DEFAULT_ADMIN_ROLE(),
                admin
            )
        );
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.GUARDIAN_ROLE(),
                admin
            )
        );
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.OPERATOR_ROLE(),
                admin
            )
        );

        // ── RelayCircuitBreaker: admin still has all roles ──
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.GUARDIAN_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.MONITOR_ROLE(), admin)
        );
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.RECOVERY_ROLE(), admin)
        );
    }

    function test_Phase8_DeployerCannotSetShieldedPoolAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                hub.OPERATOR_ROLE()
            )
        );
        hub.setShieldedPool(address(0xBAD));
    }

    function test_Phase8_DeployerCannotWireHubAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                hub.OPERATOR_ROLE()
            )
        );
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0),
                _universalVerifier: address(0),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0xBAD),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );
    }

    function test_Phase8_DeployerCannotPauseHubAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                hub.GUARDIAN_ROLE()
            )
        );
        hub.pause();
    }

    function test_Phase8_DeployerCannotRegisterVerifierAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                verifierRegistry.REGISTRY_ADMIN_ROLE()
            )
        );
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            address(0x1111),
            address(0x2222),
            keccak256("nullifier_v1")
        );
    }

    function test_Phase8_DeployerCannotPauseNullifierRegistryAfterRenounce()
        public
    {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                nullifierRegistry.EMERGENCY_ROLE()
            )
        );
        nullifierRegistry.pause();
    }

    function test_Phase8_DeployerCannotGrantRolesAfterRenounce() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        address attacker = makeAddr("attacker");

        // Pre-compute role constants to avoid staticcalls inside vm.expectRevert
        bytes32 hubAdminRole = hub.DEFAULT_ADMIN_ROLE();
        bytes32 vrAdminRole = verifierRegistry.DEFAULT_ADMIN_ROLE();
        bytes32 vrRegistryAdminRole = verifierRegistry.REGISTRY_ADMIN_ROLE();
        bytes32 nrAdminRole = nullifierRegistry.DEFAULT_ADMIN_ROLE();
        bytes32 nrRegistrarRole = nullifierRegistry.REGISTRAR_ROLE();

        // Deployer cannot re-grant admin on Hub
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                hubAdminRole
            )
        );
        hub.grantRole(hubAdminRole, attacker);

        // Deployer cannot re-grant admin on VerifierRegistry
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                vrAdminRole
            )
        );
        verifierRegistry.grantRole(vrRegistryAdminRole, attacker);

        // Deployer cannot re-grant admin on NullifierRegistry
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                nrAdminRole
            )
        );
        nullifierRegistry.grantRole(nrRegistrarRole, attacker);
    }

    function test_Phase8_AdminCanStillOperateAfterDeployerRenounces() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        vm.startPrank(admin);

        // Hub operations
        hub.setShieldedPool(address(0xBEEF));
        assertEq(hub.shieldedPool(), address(0xBEEF));

        hub.setPrivacyRouter(address(0xCAFE));
        assertEq(hub.privacyRouter(), address(0xCAFE));

        hub.registerRelayAdapter(42161, address(0xA0B1), true, 12);
        IZaseonProtocolHub.RelayInfo memory info = hub.getRelayInfo(42161);
        assertEq(info.adapter, address(0xA0B1));

        hub.pause();
        assertTrue(hub.paused());
        hub.unpause();
        assertFalse(hub.paused());

        // VerifierRegistry operations
        verifierRegistry.registerVerifier(
            VerifierRegistryV2.CircuitType.MERKLE_PROOF,
            address(0x111),
            address(0x222),
            keccak256("merkle")
        );
        assertEq(verifierRegistry.totalRegistered(), 1);

        // NullifierRegistry operations
        nullifierRegistry.pause();
        assertTrue(nullifierRegistry.paused());
        nullifierRegistry.unpause();
        assertFalse(nullifierRegistry.paused());

        vm.stopPrank();
    }

    function test_Phase8_AdminCanGrantNewRolesAfterDeployerRenounces() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        address newOperator = makeAddr("newOperator");

        vm.startPrank(admin);

        // Admin can onboard a new operator on Hub
        hub.grantRole(hub.OPERATOR_ROLE(), newOperator);
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), newOperator));

        // Admin can onboard a new registrar on NullifierRegistry
        nullifierRegistry.grantRole(
            nullifierRegistry.REGISTRAR_ROLE(),
            newOperator
        );
        assertTrue(
            nullifierRegistry.hasRole(
                nullifierRegistry.REGISTRAR_ROLE(),
                newOperator
            )
        );

        // Admin can onboard a new registry admin on VerifierRegistry
        verifierRegistry.grantRole(
            verifierRegistry.REGISTRY_ADMIN_ROLE(),
            newOperator
        );
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.REGISTRY_ADMIN_ROLE(),
                newOperator
            )
        );

        vm.stopPrank();

        // Verify the new operator can actually operate
        vm.startPrank(newOperator);
        hub.setShieldedPool(address(0xF00D));
        assertEq(hub.shieldedPool(), address(0xF00D));
        vm.stopPrank();
    }

    function test_Phase8_AdminCanRevokeRolesAfterDeployerRenounces() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        address tempOperator = makeAddr("tempOperator");
        bytes32 operatorRole = hub.OPERATOR_ROLE();

        vm.startPrank(admin);
        hub.grantRole(operatorRole, tempOperator);
        assertTrue(hub.hasRole(operatorRole, tempOperator));

        // Admin revokes the operator
        hub.revokeRole(operatorRole, tempOperator);
        assertFalse(hub.hasRole(operatorRole, tempOperator));
        vm.stopPrank();

        // Revoked operator can no longer act
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                tempOperator,
                operatorRole
            )
        );
        vm.prank(tempOperator);
        hub.setShieldedPool(address(0xBAD));
    }

    // ═══════════════════════════════════════════════════════════
    //     FULL E2E: DEPLOYMENT → TRANSFER → RENOUNCE → GOVERN
    // ═══════════════════════════════════════════════════════════

    function test_FullDeploymentLifecycle_Phase1Through8() public {
        // Phase 1-6: Already done in setUp (deploy, governance, wire)
        // Verify initial state: deployer has roles
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), deployer));
        assertTrue(hub.hasRole(hub.OPERATOR_ROLE(), deployer));

        // Phase 7: Transfer roles to admin
        _executePhase7_RoleTransfer();

        // Phase 8: Renounce deployer roles
        _executePhase8_RenounceDeployer();

        // Post Phase 8: Deployer is fully locked out
        assertFalse(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.OPERATOR_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.GUARDIAN_ROLE(), deployer));
        assertFalse(hub.hasRole(hub.UPGRADER_ROLE(), deployer));

        // Admin is the sole controller
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));

        // Governance lifecycle still works: admin proposes via governor
        address newPool = address(0xFACE);
        address[] memory targets = new address[](1);
        targets[0] = address(hub);
        uint256[] memory values = new uint256[](1);
        values[0] = 0;
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = abi.encodeWithSelector(
            hub.setShieldedPool.selector,
            newPool
        );
        string
            memory description = "Post-renounce: Set ShieldedPool via governance";

        vm.prank(voter1);
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // Vote
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(voter1);
        governor.castVote(proposalId, 1);
        vm.prank(voter2);
        governor.castVote(proposalId, 1);

        // Queue
        vm.warp(block.timestamp + 5 days + 1);
        bytes32 descHash = keccak256(bytes(description));
        governor.queue(targets, values, calldatas, descHash);

        // Execute — grant timelock OPERATOR_ROLE first
        vm.warp(block.timestamp + 1 days + 1);
        bytes32 operatorRole = hub.OPERATOR_ROLE();
        vm.prank(admin);
        hub.grantRole(operatorRole, address(upgradeTimelock));
        governor.execute(targets, values, calldatas, descHash);

        // Verify the upgrade took effect even after deployer renunciation
        assertEq(hub.shieldedPool(), newPool);
    }

    function test_Phase8_CircuitBreakerDeployerLockedOut() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // Deployer cannot call emergencyHalt
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                circuitBreaker.GUARDIAN_ROLE()
            )
        );
        circuitBreaker.emergencyHalt();

        // Admin can call emergencyHalt
        vm.prank(admin);
        circuitBreaker.emergencyHalt();
    }

    function test_Phase8_RelayProofValidatorDeployerLockedOut() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // Deployer cannot pause
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                relayProofValidator.GUARDIAN_ROLE()
            )
        );
        relayProofValidator.pause();

        // Admin can pause
        vm.prank(admin);
        relayProofValidator.pause();
        assertTrue(relayProofValidator.paused());
    }

    function test_Phase8_NoSinglePointOfFailure() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // After Phase 7+8, verify every contract still has admin as DEFAULT_ADMIN_ROLE
        // (no contract is left with zero admins, which would lock it permanently)

        // Hub: admin is the sole admin
        assertTrue(
            hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin),
            "Hub must have admin as DEFAULT_ADMIN_ROLE"
        );
        assertFalse(
            hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), deployer),
            "Hub deployer should not have DEFAULT_ADMIN_ROLE"
        );

        // NullifierRegistry
        assertTrue(
            nullifierRegistry.hasRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            ),
            "NullifierRegistry must have admin as DEFAULT_ADMIN_ROLE"
        );
        assertFalse(
            nullifierRegistry.hasRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                deployer
            ),
            "NullifierRegistry deployer should not have DEFAULT_ADMIN_ROLE"
        );

        // VerifierRegistry
        assertTrue(
            verifierRegistry.hasRole(
                verifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            ),
            "VerifierRegistry must have admin as DEFAULT_ADMIN_ROLE"
        );
        assertFalse(
            verifierRegistry.hasRole(
                verifierRegistry.DEFAULT_ADMIN_ROLE(),
                deployer
            ),
            "VerifierRegistry deployer should not have DEFAULT_ADMIN_ROLE"
        );

        // RelayProofValidator
        assertTrue(
            relayProofValidator.hasRole(
                relayProofValidator.DEFAULT_ADMIN_ROLE(),
                admin
            ),
            "RelayProofValidator must have admin as DEFAULT_ADMIN_ROLE"
        );

        // RelayCircuitBreaker
        assertTrue(
            circuitBreaker.hasRole(circuitBreaker.DEFAULT_ADMIN_ROLE(), admin),
            "RelayCircuitBreaker must have admin as DEFAULT_ADMIN_ROLE"
        );
    }

    function test_Phase8_RenounceIsIrreversible() public {
        _executePhase7_RoleTransfer();
        _executePhase8_RenounceDeployer();

        // Pre-compute role constants
        bytes32 adminRole = hub.DEFAULT_ADMIN_ROLE();
        bytes32 operatorRole = hub.OPERATOR_ROLE();

        // Deployer cannot re-add themselves — no admin role to grant with
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                adminRole
            )
        );
        hub.grantRole(operatorRole, deployer);

        // Even if deployer tries to renounce admin's role, it reverts
        // (can only renounce own roles)
        vm.expectRevert();
        hub.renounceRole(adminRole, admin);
    }
}
