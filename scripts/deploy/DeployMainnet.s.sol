// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

// Core contracts
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {BridgeCircuitBreaker} from "../../contracts/security/BridgeCircuitBreaker.sol";
import {BridgeRateLimiter} from "../../contracts/security/BridgeRateLimiter.sol";
import {EnhancedKillSwitch} from "../../contracts/security/EnhancedKillSwitch.sol";
import {ZKFraudProof} from "../../contracts/security/ZKFraudProof.sol";

/**
 * @title Soul Protocol Mainnet Deployment Script
 * @notice Deploys core contracts with production configuration
 *
 * Requirements:
 *   - DEPLOYER_PRIVATE_KEY in environment
 *   - MULTISIG_ADMIN address in environment (Gnosis Safe)
 *   - MULTISIG_GUARDIAN_1, MULTISIG_GUARDIAN_2, MULTISIG_GUARDIAN_3 addresses
 *   - Sufficient ETH for gas (~0.5 ETH estimated)
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

    // Supported L2 chain IDs
    uint256 constant ARBITRUM_ONE = 42161;
    uint256 constant OPTIMISM = 10;
    uint256 constant BASE = 8453;
    uint256 constant ZKSYNC_ERA = 324;
    uint256 constant SCROLL = 534352;
    uint256 constant LINEA = 59144;
    uint256 constant POLYGON_ZKEVM = 1101;

    // Deployed addresses
    CrossChainProofHubV3 public proofHub;
    NullifierRegistryV3 public nullifierRegistry;
    BridgeCircuitBreaker public circuitBreaker;
    BridgeRateLimiter public rateLimiter;
    EnhancedKillSwitch public killSwitch;
    ZKFraudProof public zkFraudProof;

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

        console.log("=== Soul Protocol Mainnet Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Admin (multisig):", admin);
        console.log("Chain ID:", block.chainid);

        // Safety check: warn on mainnet
        if (block.chainid == 1) {
            console.log("WARNING: Deploying to MAINNET");
        }

        vm.startBroadcast(deployerPK);

        // ========= 1. DEPLOY CORE CONTRACTS =========

        // 1a. CrossChainProofHubV3 — Main proof aggregation hub
        proofHub = new CrossChainProofHubV3();
        console.log("CrossChainProofHubV3:", address(proofHub));

        // 1b. NullifierRegistryV3 — Cross-domain nullifier tracking
        nullifierRegistry = new NullifierRegistryV3();
        console.log("NullifierRegistryV3:", address(nullifierRegistry));

        // 1c. BridgeCircuitBreaker — Anomaly detection
        circuitBreaker = new BridgeCircuitBreaker(admin);
        console.log("BridgeCircuitBreaker:", address(circuitBreaker));

        // 1d. BridgeRateLimiter — Rate limiting
        rateLimiter = new BridgeRateLimiter(admin);
        console.log("BridgeRateLimiter:", address(rateLimiter));

        // 1e. EnhancedKillSwitch — Emergency controls
        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;
        killSwitch = new EnhancedKillSwitch(admin, guardians);
        console.log("EnhancedKillSwitch:", address(killSwitch));

        // 1f. ZKFraudProof — Fraud proof verification
        // These addresses must be set via environment variables
        address stateCommitmentChain = vm.envAddress("STATE_COMMITMENT_CHAIN");
        address bondManager = vm.envAddress("BOND_MANAGER");
        address zkVerifier = vm.envAddress("ZK_VERIFIER");
        zkFraudProof = new ZKFraudProof(
            stateCommitmentChain,
            bondManager,
            zkVerifier
        );
        console.log("ZKFraudProof:", address(zkFraudProof));

        // ========= 2. CONFIGURE PROOF HUB =========

        // Deployer starts with DEFAULT_ADMIN_ROLE + EMERGENCY_ROLE only.
        // Need OPERATOR_ROLE temporarily to call addSupportedChain if it requires it.
        // addSupportedChain requires DEFAULT_ADMIN_ROLE which deployer has.
        proofHub.addSupportedChain(ARBITRUM_ONE);
        proofHub.addSupportedChain(OPTIMISM);
        proofHub.addSupportedChain(BASE);
        proofHub.addSupportedChain(ZKSYNC_ERA);
        proofHub.addSupportedChain(SCROLL);
        proofHub.addSupportedChain(LINEA);
        proofHub.addSupportedChain(POLYGON_ZKEVM);

        // setRateLimits requires DEFAULT_ADMIN_ROLE
        proofHub.setRateLimits(MAX_PROOFS_PER_HOUR, MAX_VALUE_PER_HOUR);

        // ========= 3. TRANSFER ALL ROLES TO MULTISIG =========

        // ProofHub: grant all roles to multisig
        bytes32 adminRole = proofHub.DEFAULT_ADMIN_ROLE();
        proofHub.grantRole(adminRole, admin);
        proofHub.grantRole(proofHub.EMERGENCY_ROLE(), admin);
        proofHub.grantRole(proofHub.VERIFIER_ADMIN_ROLE(), admin);
        proofHub.grantRole(proofHub.OPERATOR_ROLE(), admin);

        // NullifierRegistryV3: grant all roles to multisig
        nullifierRegistry.grantRole(
            nullifierRegistry.DEFAULT_ADMIN_ROLE(),
            admin
        );
        nullifierRegistry.grantRole(nullifierRegistry.REGISTRAR_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.BRIDGE_ROLE(), admin);
        nullifierRegistry.grantRole(nullifierRegistry.EMERGENCY_ROLE(), admin);

        // KillSwitch: guardians are set via constructor, admin controls escalation

        // ZKFraudProof: transfer admin
        zkFraudProof.grantRole(zkFraudProof.DEFAULT_ADMIN_ROLE(), admin);

        // ========= 4. RENOUNCE DEPLOYER ROLES =========
        // CRITICAL: Deployer must NOT retain any elevated privileges

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

        // ZKFraudProof
        zkFraudProof.renounceRole(zkFraudProof.PROVER_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.VERIFIER_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.OPERATOR_ROLE(), deployer);
        zkFraudProof.renounceRole(zkFraudProof.DEFAULT_ADMIN_ROLE(), deployer);

        vm.stopBroadcast();

        // ========= 5. LOG DEPLOYMENT =========
        _logDeployment();
    }

    function _logDeployment() internal view {
        console.log("\n=== Deployment Complete ===");
        console.log("CrossChainProofHubV3:", address(proofHub));
        console.log("NullifierRegistryV3:", address(nullifierRegistry));
        console.log("BridgeCircuitBreaker:", address(circuitBreaker));
        console.log("BridgeRateLimiter:", address(rateLimiter));
        console.log("EnhancedKillSwitch:", address(killSwitch));
        console.log("ZKFraudProof:", address(zkFraudProof));
        console.log("\nPost-deploy checklist:");
        console.log("  1. Verify all contracts on Etherscan");
        console.log("  2. Configure ZKFraudProof external contracts");
        console.log(
            "  3. Set up relayer/challenger roles on ProofHub (via multisig)"
        );
        console.log("  4. Configure verifier contracts");
        console.log("  5. Run verify-deployment.ts");
        console.log("  6. Update SDK addresses in mainnet-addresses.ts");
        console.log(
            "  7. CRITICAL: Run ConfirmRoleSeparation.s.sol from multisig"
        );
        console.log(
            "     - Calls confirmRoleSeparation() on ProofHub & ZKBoundStateLocks"
        );
        console.log(
            "     - Admin must NOT hold operational roles before calling"
        );
    }
}
