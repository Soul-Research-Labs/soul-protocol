// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

// ── Phase 1: Security ──
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {RelayCircuitBreaker} from "../../contracts/security/RelayCircuitBreaker.sol";
import {RelayRateLimiter} from "../../contracts/security/RelayRateLimiter.sol";
import {EnhancedKillSwitch} from "../../contracts/security/EnhancedKillSwitch.sol";
import {ZKFraudProof} from "../../contracts/security/ZKFraudProof.sol";
import {RelayProofValidator} from "../../contracts/security/RelayProofValidator.sol";

// ── Phase 2: Verifiers ──
import {VerifierRegistryV2} from "../../contracts/verifiers/VerifierRegistryV2.sol";
import {ZaseonUniversalVerifier} from "../../contracts/verifiers/ZaseonUniversalVerifier.sol";
import {UltraHonkAdapter} from "../../contracts/verifiers/adapters/UltraHonkAdapter.sol";

// ── Phase 3: Primitives ──
import {ZKBoundStateLocks} from "../../contracts/primitives/ZKBoundStateLocks.sol";
import {ProofCarryingContainer} from "../../contracts/primitives/ProofCarryingContainer.sol";
import {CrossDomainNullifierAlgebra} from "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";
import {PolicyBoundProofs} from "../../contracts/primitives/PolicyBoundProofs.sol";

// ── Phase 3.5: Liquidity ──
import {CrossChainLiquidityVault} from "../../contracts/bridge/CrossChainLiquidityVault.sol";

// ── Phase 4: Hub ──
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";

// ── Phase 5: Governance ──
import {ZaseonToken} from "../../contracts/governance/ZaseonToken.sol";
import {ZaseonGovernor} from "../../contracts/governance/ZaseonGovernor.sol";
import {ZaseonUpgradeTimelock} from "../../contracts/governance/ZaseonUpgradeTimelock.sol";

/**
 * @title ZASEON Mainnet Deployment Script
 * @notice Full 8-phase deployment: Security → Verifiers → Primitives → Hub → Governance → Wiring → Roles → Verification
 *
 * Requirements:
 *   - DEPLOYER_PRIVATE_KEY in environment
 *   - MULTISIG_ADMIN address in environment (Gnosis Safe)
 *   - MULTISIG_GUARDIAN_1, MULTISIG_GUARDIAN_2, MULTISIG_GUARDIAN_3 addresses
 *   - STATE_COMMITMENT_CHAIN, BOND_MANAGER, ZK_VERIFIER for ZKFraudProof
 *   - Sufficient ETH for gas (~2.0 ETH estimated)
 *
 * Usage:
 *   forge script scripts/deploy/DeployMainnet.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     --verify \
 *     --etherscan-api-key $ETHERSCAN_API_KEY \
 *     -vvv
 *
 * Dry run (simulation only):
 *   forge script scripts/deploy/DeployMainnet.s.sol \
 *     --rpc-url $RPC_URL \
 *     -vvv
 */
contract DeployMainnet is Script {
    // ========= CONFIGURATION =========

    // Timelock delays
    uint256 constant CHALLENGE_PERIOD = 1 hours;
    uint256 constant MIN_RELAYER_STAKE = 0.1 ether;
    uint256 constant MIN_CHALLENGER_STAKE = 0.05 ether;

    // Rate limits
    uint256 constant MAX_PROOFS_PER_HOUR = 500;
    uint256 constant MAX_VALUE_PER_HOUR = 500 ether;

    // Bridge rate limiter
    uint256 constant RATE_LIMIT_HOURLY = 1000 ether;
    uint256 constant RATE_LIMIT_DAILY = 10000 ether;

    // Production L2 chain IDs
    uint256 constant ARBITRUM_ONE = 42161;
    uint256 constant OPTIMISM = 10;
    uint256 constant BASE = 8453;
    uint256 constant SCROLL = 534352;
    uint256 constant LINEA = 59144;
    uint256 constant ZKSYNC_ERA = 324;
    uint256 constant POLYGON_ZKEVM = 1101;
    uint256 constant MANTLE = 5000;
    uint256 constant BLAST = 81457;
    uint256 constant TAIKO = 167000;
    uint256 constant MODE = 34443;
    uint256 constant MANTA_PACIFIC = 169;

    // ========= DEPLOYED CONTRACTS =========

    // Phase 1: Security
    CrossChainProofHubV3 public proofHub;
    NullifierRegistryV3 public nullifierRegistry;
    RelayCircuitBreaker public circuitBreaker;
    RelayRateLimiter public rateLimiter;
    EnhancedKillSwitch public killSwitch;
    ZKFraudProof public zkFraudProof;
    RelayProofValidator public relayProofValidator;

    // Phase 2: Verifiers
    VerifierRegistryV2 public verifierRegistry;
    ZaseonUniversalVerifier public universalVerifier;

    // Phase 3: Primitives
    ZKBoundStateLocks public zkBoundStateLocks;
    ProofCarryingContainer public proofCarryingContainer;
    CrossDomainNullifierAlgebra public cdna;
    PolicyBoundProofs public policyBoundProofs;

    // Phase 3.5: Liquidity
    CrossChainLiquidityVault public liquidityVault;

    // Phase 4: Hub
    ZaseonProtocolHub public hub;

    // Phase 5: Governance
    ZaseonToken public zaseonToken;
    ZaseonGovernor public governor;
    ZaseonUpgradeTimelock public upgradeTimelock;

    function run() external {
        // ========= LOAD CONFIGURATION =========
        address admin = vm.envAddress("MULTISIG_ADMIN");
        address guardian1 = vm.envAddress("MULTISIG_GUARDIAN_1");
        address guardian2 = vm.envAddress("MULTISIG_GUARDIAN_2");
        address guardian3 = vm.envAddress("MULTISIG_GUARDIAN_3");

        require(admin != address(0), "MULTISIG_ADMIN not set");
        require(guardian1 != address(0), "MULTISIG_GUARDIAN_1 not set");
        require(guardian2 != address(0), "MULTISIG_GUARDIAN_2 not set");
        require(guardian3 != address(0), "MULTISIG_GUARDIAN_3 not set");

        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);

        console.log("=== ZASEON Mainnet Deployment (Full) ===");
        console.log("Deployer:", deployer);
        console.log("Admin (multisig):", admin);
        console.log("Chain ID:", block.chainid);

        if (block.chainid == 1) {
            console.log("WARNING: Deploying to MAINNET");
        }

        vm.startBroadcast(deployerPK);

        // ======== PHASE 1: SECURITY CONTRACTS ========
        console.log("\n--- Phase 1: Security ---");

        proofHub = new CrossChainProofHubV3();
        console.log("CrossChainProofHubV3:", address(proofHub));

        nullifierRegistry = new NullifierRegistryV3();
        console.log("NullifierRegistryV3:", address(nullifierRegistry));

        circuitBreaker = new RelayCircuitBreaker(admin);
        console.log("RelayCircuitBreaker:", address(circuitBreaker));

        rateLimiter = new RelayRateLimiter(admin);
        console.log("RelayRateLimiter:", address(rateLimiter));

        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;
        killSwitch = new EnhancedKillSwitch(admin, guardians);
        console.log("EnhancedKillSwitch:", address(killSwitch));

        address stateCommitmentChain = vm.envAddress("STATE_COMMITMENT_CHAIN");
        address bondManager = vm.envAddress("BOND_MANAGER");
        address zkVerifier = vm.envAddress("ZK_VERIFIER");
        zkFraudProof = new ZKFraudProof(
            stateCommitmentChain,
            bondManager,
            zkVerifier
        );
        console.log("ZKFraudProof:", address(zkFraudProof));

        relayProofValidator = new RelayProofValidator();
        console.log("RelayProofValidator:", address(relayProofValidator));

        // ======== PHASE 2: VERIFIER INFRASTRUCTURE ========
        console.log("\n--- Phase 2: Verifiers ---");

        verifierRegistry = new VerifierRegistryV2();
        console.log("VerifierRegistryV2:", address(verifierRegistry));

        universalVerifier = new ZaseonUniversalVerifier(deployer);
        console.log("ZaseonUniversalVerifier:", address(universalVerifier));

        // ======== PHASE 3: PRIMITIVES ========
        console.log("\n--- Phase 3: Primitives ---");

        zkBoundStateLocks = new ZKBoundStateLocks();
        console.log("ZKBoundStateLocks:", address(zkBoundStateLocks));

        proofCarryingContainer = new ProofCarryingContainer();
        console.log("ProofCarryingContainer:", address(proofCarryingContainer));

        cdna = new CrossDomainNullifierAlgebra();
        console.log("CrossDomainNullifierAlgebra:", address(cdna));

        policyBoundProofs = new PolicyBoundProofs();
        console.log("PolicyBoundProofs:", address(policyBoundProofs));

        // ======== PHASE 3.5: LIQUIDITY VAULT ========
        console.log("\n--- Phase 3.5: Liquidity ---");

        // Deploy vault with deployer as temporary PRIVACY_HUB_ROLE holder.
        // After CrossChainPrivacyHub is deployed per-L2, the multisig must:
        //   1. vault.grantRole(PRIVACY_HUB_ROLE, <privacyHubAddress>)
        //   2. vault.revokeRole(PRIVACY_HUB_ROLE, deployer)
        liquidityVault = new CrossChainLiquidityVault(
            admin,       // DEFAULT_ADMIN_ROLE
            admin,       // OPERATOR_ROLE + SETTLER_ROLE
            guardian1,   // GUARDIAN_ROLE
            deployer,    // PRIVACY_HUB_ROLE (temporary, re-assign to actual hub later)
            5000         // 50% of protocol fees go to LPs
        );
        console.log("CrossChainLiquidityVault:", address(liquidityVault));

        // ======== PHASE 4: HUB ========
        console.log("\n--- Phase 4: Hub ---");

        hub = new ZaseonProtocolHub();
        console.log("ZaseonProtocolHub:", address(hub));

        // ======== PHASE 5: GOVERNANCE ========
        console.log("\n--- Phase 5: Governance ---");

        zaseonToken = new ZaseonToken();
        console.log("ZaseonToken:", address(zaseonToken));

        // Timelock: admin is proposer + executor, governor will be added after
        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // anyone can execute once queued
        upgradeTimelock = new ZaseonUpgradeTimelock(
            1 days,
            proposers,
            executors,
            admin
        );
        console.log("ZaseonUpgradeTimelock:", address(upgradeTimelock));

        governor = new ZaseonGovernor(
            IVotes(address(zaseonToken)),
            TimelockController(payable(address(upgradeTimelock))),
            0,
            0,
            0,
            0 // defaults: 1d delay, 5d period, 100k threshold, 4% quorum
        );
        console.log("ZaseonGovernor:", address(governor));

        // Grant governor proposer/executor/canceller on timelock
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

        // ======== PHASE 6: CONFIGURE PROOF HUB + WIRING ========
        console.log("\n--- Phase 6: Configuration ---");

        // Register production L2 chains
        proofHub.addSupportedChain(ARBITRUM_ONE);
        proofHub.addSupportedChain(OPTIMISM);
        proofHub.addSupportedChain(BASE);
        proofHub.addSupportedChain(SCROLL);
        proofHub.addSupportedChain(LINEA);
        proofHub.addSupportedChain(ZKSYNC_ERA);
        proofHub.addSupportedChain(POLYGON_ZKEVM);
        proofHub.addSupportedChain(MANTLE);
        proofHub.addSupportedChain(BLAST);
        proofHub.addSupportedChain(TAIKO);
        proofHub.addSupportedChain(MODE);
        proofHub.addSupportedChain(MANTA_PACIFIC);
        proofHub.setRateLimits(MAX_PROOFS_PER_HOUR, MAX_VALUE_PER_HOUR);

        // Wire the Hub with all component addresses
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(verifierRegistry),
                _universalVerifier: address(universalVerifier),
                _crossChainMessageRelay: address(0), // deployed separately per L2
                _crossChainPrivacyHub: address(0), // deployed separately per L2
                _stealthAddressRegistry: address(0), // upgradeable, deployed separately
                _privateRelayerNetwork: address(0), // deployed separately
                _viewKeyRegistry: address(0), // deployed separately
                _shieldedPool: address(0), // deployed separately
                _nullifierManager: address(nullifierRegistry),
                _complianceOracle: address(0), // deployed separately
                _proofTranslator: address(0), // deployed separately
                _privacyRouter: address(0), // deployed separately
                _relayProofValidator: address(relayProofValidator),
                _zkBoundStateLocks: address(zkBoundStateLocks),
                _proofCarryingContainer: address(proofCarryingContainer),
                _crossDomainNullifierAlgebra: address(cdna),
                _policyBoundProofs: address(policyBoundProofs),
                _multiProver: address(0), // deployed separately
                _relayWatchtower: address(0), // deployed separately
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(liquidityVault)
            })
        );
        console.log("Hub wired with core components");

        // Set Hub governance pointers
        hub.setTimelock(address(upgradeTimelock));
        hub.setUpgradeTimelock(address(upgradeTimelock));

        // Wire relay circuit breaker (not in wireAll struct)
        hub.setRelayCircuitBreaker(address(circuitBreaker));
        console.log("RelayCircuitBreaker wired to Hub");

        // Lock PCC verification to production mode (one-way, irreversible)
        proofCarryingContainer.lockVerificationMode();
        console.log("PCC verification mode locked (production)");

        // ======== PHASE 7: TRANSFER ROLES TO MULTISIG ========
        console.log("\n--- Phase 7: Role Transfer ---");

        // ProofHub
        bytes32 adminRole = proofHub.DEFAULT_ADMIN_ROLE();
        proofHub.grantRole(adminRole, admin);
        proofHub.grantRole(proofHub.EMERGENCY_ROLE(), admin);
        proofHub.grantRole(proofHub.VERIFIER_ADMIN_ROLE(), admin);
        proofHub.grantRole(proofHub.OPERATOR_ROLE(), admin);

        // NullifierRegistryV3
        nullifierRegistry.grantRole(
            nullifierRegistry.DEFAULT_ADMIN_ROLE(),
            admin
        );
        nullifierRegistry.grantRole(nullifierRegistry.REGISTRAR_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.BRIDGE_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.EMERGENCY_ROLE(), admin);

        // VerifierRegistryV2
        verifierRegistry.grantRole(
            verifierRegistry.DEFAULT_ADMIN_ROLE(),
            admin
        );
        verifierRegistry.grantRole(
            verifierRegistry.REGISTRY_ADMIN_ROLE(),
            admin
        );
        verifierRegistry.grantRole(verifierRegistry.GUARDIAN_ROLE(), admin);

        // ZaseonProtocolHub
        hub.grantRole(hub.DEFAULT_ADMIN_ROLE(), admin);
        hub.grantRole(hub.OPERATOR_ROLE(), admin);
        hub.grantRole(hub.GUARDIAN_ROLE(), admin);
        hub.grantRole(hub.UPGRADER_ROLE(), admin);

        // ZKFraudProof
        zkFraudProof.grantRole(zkFraudProof.DEFAULT_ADMIN_ROLE(), admin);

        // CrossChainLiquidityVault — admin already set via constructor
        // PRIVACY_HUB_ROLE stays with deployer temporarily until PrivacyHub is deployed
        // Multisig will reassign: vault.grantRole(PRIVACY_HUB_ROLE, privacyHub)

        // ======== PHASE 8: RENOUNCE DEPLOYER ROLES ========
        console.log("\n--- Phase 8: Renounce Deployer ---");

        // ProofHub
        proofHub.renounceRole(proofHub.EMERGENCY_ROLE(), deployer);
        proofHub.renounceRole(adminRole, deployer);

        // NullifierRegistryV3
        nullifierRegistry.renounceRole(
            nullifierRegistry.EMERGENCY_ROLE(),
            deployer
        );
        nullifierRegistry.renounceRole(
            nullifierRegistry.BRIDGE_ROLE(),
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

        // VerifierRegistryV2
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

        // ZaseonProtocolHub
        hub.renounceRole(hub.UPGRADER_ROLE(), deployer);
        hub.renounceRole(hub.GUARDIAN_ROLE(), deployer);
        hub.renounceRole(hub.OPERATOR_ROLE(), deployer);
        hub.renounceRole(hub.DEFAULT_ADMIN_ROLE(), deployer);

        // ZKFraudProof
        zkFraudProof.renounceRole(zkFraudProof.PROVER_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.VERIFIER_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.OPERATOR_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.DEFAULT_ADMIN_ROLE(), deployer);

        // CrossChainLiquidityVault — renounce deployer's temporary PRIVACY_HUB_ROLE
        // NOTE: Only do this AFTER the multisig has granted PRIVACY_HUB_ROLE to the real PrivacyHub
        // For safety, we leave the deployer's PRIVACY_HUB_ROLE here and move renounce to
        // ConfigureCrossChain.s.sol which runs after PrivacyHub deployment

        vm.stopBroadcast();

        // ========= LOG =========
        _logDeployment();
    }

    function _logDeployment() internal view {
        console.log("\n=== Full Deployment Complete ===");
        console.log("\n-- Security --");
        console.log("CrossChainProofHubV3:", address(proofHub));
        console.log("NullifierRegistryV3:", address(nullifierRegistry));
        console.log("RelayCircuitBreaker:", address(circuitBreaker));
        console.log("RelayRateLimiter:", address(rateLimiter));
        console.log("EnhancedKillSwitch:", address(killSwitch));
        console.log("ZKFraudProof:", address(zkFraudProof));
        console.log("RelayProofValidator:", address(relayProofValidator));
        console.log("\n-- Verifiers --");
        console.log("VerifierRegistryV2:", address(verifierRegistry));
        console.log("ZaseonUniversalVerifier:", address(universalVerifier));
        console.log("\n-- Primitives --");
        console.log("ZKBoundStateLocks:", address(zkBoundStateLocks));
        console.log("ProofCarryingContainer:", address(proofCarryingContainer));
        console.log("CrossDomainNullifierAlgebra:", address(cdna));
        console.log("PolicyBoundProofs:", address(policyBoundProofs));
        console.log("\n-- Liquidity --");
        console.log("CrossChainLiquidityVault:", address(liquidityVault));
        console.log("\n-- Hub --");
        console.log("ZaseonProtocolHub:", address(hub));
        console.log("\n-- Governance --");
        console.log("ZaseonToken:", address(zaseonToken));
        console.log("ZaseonGovernor:", address(governor));
        console.log("ZaseonUpgradeTimelock:", address(upgradeTimelock));
        console.log("\nPost-deploy checklist:");
        console.log("  1. Verify all contracts on Etherscan");
        console.log(
            "  2. Deploy L2 bridge adapters (DeployL2Bridges.s.sol) on all supported L2s"
        );
        console.log("  3. Run ConfigureCrossChain.s.sol to link L1<->L2");
        console.log(
            "  4. Register UltraHonk verifier adapters via multisig (batchRegisterVerifiers)"
        );
        console.log(
            "  5. Wire remaining Hub components (shieldedPool, privacyRouter, etc.) via multisig"
        );
        console.log(
            "  6. Grant PRIVACY_HUB_ROLE to deployed CrossChainPrivacyHub on LiquidityVault"
        );
        console.log("  7. Run verify-deployment.ts");
        console.log(
            "  7. CRITICAL: Run ConfirmRoleSeparation.s.sol from multisig"
        );
    }
}
