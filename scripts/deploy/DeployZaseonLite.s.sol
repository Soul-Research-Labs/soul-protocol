// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../contracts/core/NullifierRegistryV3.sol";
import "../../contracts/primitives/ProofCarryingContainer.sol";
import "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";
import "../../contracts/privacy/UniversalShieldedPool.sol";
import "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import "../../contracts/verifiers/generated/ShieldedPoolVerifier.sol";

/**
 * @title DeployZaseonLite
 * @notice Deploys the "Zaseon Lite" auditable core — a minimal cross-chain private
 *         note transfer system that forms the security-critical foundation.
 *
 * @dev This deploys exactly 6 contracts (the auditable core):
 *        1. ShieldedPoolVerifier   — generated ZK verifier (dependency)
 *        2. NullifierRegistryV3    — double-spend prevention via merkle tree
 *        3. ProofCarryingContainer — bundles state transitions with ZK proofs
 *        4. CrossDomainNullifierAlgebra — cross-chain nullifier derivation (CDNA)
 *        5. UniversalShieldedPool  — deposit/withdraw with shielded commitments
 *        6. OptimismBridgeAdapter  — single bridge adapter (swap for target L2)
 *
 *      Everything else in the protocol (governance, relayer infra, compliance,
 *      emergency systems, fee markets, privacy tiers, intent routing) is an
 *      OPTIONAL MODULE layered on top.
 *
 *      This separation exists because:
 *        - The auditable core is ~5 contracts vs ~242 in the full protocol
 *        - Security audits can focus on the critical path
 *        - The core has a minimal attack surface
 *        - Each optional module can be audited independently
 *
 * Usage (dry-run):
 *   forge script scripts/deploy/DeployZaseonLite.s.sol \
 *     --rpc-url $RPC_URL -vvv
 *
 * Usage (broadcast):
 *   forge script scripts/deploy/DeployZaseonLite.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify -vvv
 */
contract DeployZaseonLite is Script {
    // Deployed references
    ShieldedPoolVerifier public verifier;
    NullifierRegistryV3 public nullifierRegistry;
    ProofCarryingContainer public pcc;
    CrossDomainNullifierAlgebra public cdna;
    UniversalShieldedPool public shieldedPool;
    OptimismBridgeAdapter public bridgeAdapter;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address admin = vm.envOr("ADMIN_ADDRESS", deployer);

        console.log("=== Zaseon Lite Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Admin:   ", admin);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // =====================================================================
        // Phase 1: Verifier (dependency for ShieldedPool)
        // =====================================================================
        verifier = new ShieldedPoolVerifier();
        console.log("[1/6] ShieldedPoolVerifier:", address(verifier));

        // =====================================================================
        // Phase 2: Core — NullifierRegistryV3
        // =====================================================================
        nullifierRegistry = new NullifierRegistryV3();
        console.log("[2/6] NullifierRegistryV3: ", address(nullifierRegistry));

        // =====================================================================
        // Phase 3: Core — ProofCarryingContainer
        // =====================================================================
        pcc = new ProofCarryingContainer();
        console.log("[3/6] ProofCarryingContainer:", address(pcc));

        // =====================================================================
        // Phase 4: Core — CrossDomainNullifierAlgebra
        // =====================================================================
        cdna = new CrossDomainNullifierAlgebra();
        console.log("[4/6] CrossDomainNullifierAlgebra:", address(cdna));

        // =====================================================================
        // Phase 5: Core — UniversalShieldedPool
        // =====================================================================
        // testMode=false for production; set to true for testnet
        bool testMode = block.chainid != 1; // auto-detect: testMode on non-mainnet
        shieldedPool = new UniversalShieldedPool(
            admin,
            address(verifier),
            testMode
        );
        console.log("[5/6] UniversalShieldedPool:", address(shieldedPool));

        // =====================================================================
        // Phase 6: Bridge — Single Adapter (Optimism)
        // Swap this import for the target L2's adapter:
        //   ArbitrumBridgeAdapter, BaseBridgeAdapter, zkSyncBridgeAdapter, etc.
        // =====================================================================
        bridgeAdapter = new OptimismBridgeAdapter(admin);
        console.log("[6/6] OptimismBridgeAdapter:", address(bridgeAdapter));

        // =====================================================================
        // Wiring: Minimal cross-references
        // =====================================================================

        // ShieldedPool needs registrar access to NullifierRegistryV3
        nullifierRegistry.addRegistrar(address(shieldedPool));

        // Bridge adapter needs BRIDGE_ROLE on NullifierRegistryV3
        nullifierRegistry.grantRole(
            nullifierRegistry.BRIDGE_ROLE(),
            address(bridgeAdapter)
        );

        // Grant admin roles
        if (admin != deployer) {
            nullifierRegistry.grantRole(
                nullifierRegistry.DEFAULT_ADMIN_ROLE(),
                admin
            );
            pcc.grantRole(pcc.DEFAULT_ADMIN_ROLE(), admin);
            cdna.grantRole(cdna.DEFAULT_ADMIN_ROLE(), admin);
        }

        vm.stopBroadcast();

        // =====================================================================
        // Post-deploy validation
        // =====================================================================
        require(
            address(nullifierRegistry) != address(0),
            "NullifierRegistry not deployed"
        );
        require(address(pcc) != address(0), "PCC not deployed");
        require(address(cdna) != address(0), "CDNA not deployed");
        require(
            address(shieldedPool) != address(0),
            "ShieldedPool not deployed"
        );
        require(
            address(bridgeAdapter) != address(0),
            "BridgeAdapter not deployed"
        );

        _logSummary(admin, testMode);
    }

    function _logSummary(address admin, bool testMode) internal view {
        console.log("");
        console.log("=== Zaseon Lite — Deployment Complete ===");
        console.log("");
        console.log("AUDITABLE CORE (6 contracts):");
        console.log("  ShieldedPoolVerifier:      ", address(verifier));
        console.log(
            "  NullifierRegistryV3:       ",
            address(nullifierRegistry)
        );
        console.log("  ProofCarryingContainer:    ", address(pcc));
        console.log("  CrossDomainNullifierAlgebra:", address(cdna));
        console.log("  UniversalShieldedPool:     ", address(shieldedPool));
        console.log("  OptimismBridgeAdapter:     ", address(bridgeAdapter));
        console.log("");
        console.log("MODE:", testMode ? "TESTNET (relaxed)" : "PRODUCTION");
        console.log("ADMIN:", admin);
        console.log("");
        console.log("NEXT STEPS:");
        console.log("  1. Verify all contracts on block explorer");
        console.log(
            "  2. If production: call pcc.requestLockVerificationMode()"
        );
        console.log("     then after 48h: pcc.executeLockVerificationMode()");
        console.log("  3. Register supported assets on ShieldedPool");
        console.log(
            "  4. Configure bridge adapter with L1/L2 messenger addresses"
        );
        console.log("  5. (Optional) Deploy additional modules:");
        console.log("     - Governance: DeployMainnet.s.sol Phase 5");
        console.log("     - Relayers:   DeployRelayerInfrastructure.s.sol");
        console.log("     - Privacy:    DeployPrivacyComponents.s.sol");
        console.log("     - Security:   DeploySecurityComponents.s.sol");
        console.log("");
        console.log("SECURITY REMINDER:");
        console.log(
            "  The auditable core handles ALL value-bearing operations."
        );
        console.log(
            "  Optional modules add UX/governance/monitoring but do NOT"
        );
        console.log("  affect the security of note transfers.");
    }
}
