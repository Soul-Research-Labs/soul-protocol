// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../contracts/privacy/UniversalShieldedPool.sol";
import "../../contracts/privacy/StealthAddressRegistry.sol";
import "../../contracts/privacy/ViewKeyRegistry.sol";
import "../../contracts/privacy/CrossChainPrivacyHub.sol";
import "../../contracts/privacy/DataAvailabilityOracle.sol";
import "../../contracts/privacy/BatchAccumulator.sol";
import "../../contracts/privacy/PrivacyZoneManager.sol";

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployPrivacyComponents
 * @notice Deploys the full privacy middleware stack for ZASEON.
 *
 * @dev Deployment order is dependency-aware:
 *   Phase 1 — Standalone registries (no cross-contract deps)
 *              StealthAddressRegistry, ViewKeyRegistry, DataAvailabilityOracle,
 *              PrivacyZoneManager
 *   Phase 2 — Shielded pool (standalone, optional verifier)
 *              UniversalShieldedPool
 *   Phase 3 — Cross-Chain Privacy Hub (standalone, wired later)
 *              CrossChainPrivacyHub (UUPS proxy)
 *   Phase 4 — Batch accumulator (depends on Phase 3 + verifier)
 *              BatchAccumulator (UUPS proxy)
 *   Phase 5 — Cross-contract wiring (roles, references)
 *
 * Environment Variables:
 *   PRIVATE_KEY            — Deployer private key (required)
 *   GUARDIAN               — Guardian address for CrossChainPrivacyHub (optional; defaults to deployer)
 *   FEE_RECIPIENT          — Protocol fee recipient (optional; defaults to deployer)
 *   WITHDRAWAL_VERIFIER    — Verifier contract for ShieldedPool withdrawals (optional; address(0) if unset)
 *   PROOF_VERIFIER         — Proof verifier for BatchAccumulator (optional; uses withdrawal verifier if unset)
 *   TEST_MODE              — Set to "true" to enable test mode (optional; default false)
 *
 * Usage (dry-run):
 *   forge script scripts/deploy/DeployPrivacyComponents.s.sol \
 *     --rpc-url $RPC_URL -vvv
 *
 * Usage (broadcast):
 *   forge script scripts/deploy/DeployPrivacyComponents.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify -vvv
 */
contract DeployPrivacyComponents is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        address guardian = _envAddressOr("GUARDIAN", deployer);
        address admin = _envAddressOr("MULTISIG_ADMIN", guardian);
        address feeRecipient = _envAddressOr("FEE_RECIPIENT", deployer);
        address withdrawalVerifier = _envAddressOr(
            "WITHDRAWAL_VERIFIER",
            address(0)
        );
        address proofVerifier = _envAddressOr(
            "PROOF_VERIFIER",
            withdrawalVerifier
        );
        bool testMode = _envBoolOr("TEST_MODE", false);

        console.log("========================================");
        console.log("  Deploy Privacy Components");
        console.log("========================================");
        console.log("Deployer:              ", deployer);
        console.log("Chain ID:              ", block.chainid);
        console.log("Guardian:              ", guardian);
        console.log("Multisig Admin:        ", admin);
        console.log("Fee Recipient:         ", feeRecipient);
        console.log("Withdrawal Verifier:   ", withdrawalVerifier);
        console.log("Proof Verifier:        ", proofVerifier);
        console.log("Test Mode:             ", testMode);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // ─── Phase 1: Standalone Registries ─────────────────────────
        console.log("--- Phase 1: Standalone Registries ---");

        // StealthAddressRegistry (UUPS proxy)
        StealthAddressRegistry stealthImpl = new StealthAddressRegistry();
        ERC1967Proxy stealthProxy = new ERC1967Proxy(
            address(stealthImpl),
            abi.encodeWithSelector(
                StealthAddressRegistry.initialize.selector,
                deployer
            )
        );
        StealthAddressRegistry stealth = StealthAddressRegistry(
            address(stealthProxy)
        );
        console.log("StealthAddressRegistry:", address(stealth));

        // ViewKeyRegistry (UUPS proxy)
        ViewKeyRegistry viewKeyImpl = new ViewKeyRegistry();
        ERC1967Proxy viewKeyProxy = new ERC1967Proxy(
            address(viewKeyImpl),
            abi.encodeWithSelector(
                ViewKeyRegistry.initialize.selector,
                deployer
            )
        );
        ViewKeyRegistry viewKey = ViewKeyRegistry(address(viewKeyProxy));
        console.log("ViewKeyRegistry:       ", address(viewKey));

        // DataAvailabilityOracle
        DataAvailabilityOracle daOracle = new DataAvailabilityOracle(deployer);
        console.log("DA Oracle:             ", address(daOracle));

        // PrivacyZoneManager
        PrivacyZoneManager zoneManager = new PrivacyZoneManager(
            deployer,
            testMode
        );
        console.log("PrivacyZoneManager:    ", address(zoneManager));

        // ─── Phase 2: Shielded Pool ────────────────────────────────
        console.log("");
        console.log("--- Phase 2: Shielded Pool ---");

        UniversalShieldedPool shieldedPool = new UniversalShieldedPool(
            deployer,
            withdrawalVerifier,
            testMode
        );
        console.log("ShieldedPool:          ", address(shieldedPool));

        // ─── Phase 3: Cross-Chain Privacy Hub ──────────────────────
        console.log("");
        console.log("--- Phase 3: Cross-Chain Privacy Hub ---");

        CrossChainPrivacyHub hubImpl = new CrossChainPrivacyHub();
        ERC1967Proxy hubProxy = new ERC1967Proxy(
            address(hubImpl),
            abi.encodeWithSelector(
                CrossChainPrivacyHub.initialize.selector,
                deployer,
                guardian,
                feeRecipient
            )
        );
        CrossChainPrivacyHub privacyHub = CrossChainPrivacyHub(
            payable(address(hubProxy))
        );
        console.log("CrossChainPrivacyHub:  ", address(privacyHub));

        // ─── Phase 4: Batch Accumulator ────────────────────────────
        console.log("");
        console.log("--- Phase 4: Batch Accumulator ---");

        BatchAccumulator batch;
        if (proofVerifier != address(0)) {
            BatchAccumulator batchImpl = new BatchAccumulator();
            ERC1967Proxy batchProxy = new ERC1967Proxy(
                address(batchImpl),
                abi.encodeWithSelector(
                    BatchAccumulator.initialize.selector,
                    deployer,
                    proofVerifier,
                    address(privacyHub)
                )
            );
            batch = BatchAccumulator(address(batchProxy));
            console.log("BatchAccumulator:      ", address(batch));
        } else {
            console.log(
                "BatchAccumulator:       SKIPPED (no PROOF_VERIFIER set)"
            );
        }

        // ─── Phase 5: Cross-contract Wiring ────────────────────────
        console.log("");
        console.log("--- Phase 5: Cross-contract Wiring ---");

        // Grant RELAYER_ROLE on ShieldedPool to the CrossChainPrivacyHub
        // so it can process cross-chain deposits/withdrawals
        bytes32 relayerRole = shieldedPool.RELAYER_ROLE();
        shieldedPool.grantRole(relayerRole, address(privacyHub));
        console.log("Granted RELAYER_ROLE on ShieldedPool to PrivacyHub");

        // ─── Phase 6: Transfer Roles to Multisig ───────────────────
        console.log("");
        console.log("--- Phase 6: Transfer Roles to Multisig ---");

        // StealthAddressRegistry
        stealth.grantRole(stealth.DEFAULT_ADMIN_ROLE(), admin);
        stealth.grantRole(stealth.OPERATOR_ROLE(), admin);
        stealth.grantRole(stealth.ANNOUNCER_ROLE(), admin);
        stealth.grantRole(stealth.UPGRADER_ROLE(), admin);

        // ViewKeyRegistry
        viewKey.grantRole(viewKey.DEFAULT_ADMIN_ROLE(), admin);
        viewKey.grantRole(viewKey.ADMIN_ROLE(), admin);
        viewKey.grantRole(viewKey.REGISTRAR_ROLE(), admin);

        // DataAvailabilityOracle
        daOracle.grantRole(daOracle.DEFAULT_ADMIN_ROLE(), admin);
        daOracle.grantRole(daOracle.DA_ADMIN_ROLE(), admin);
        daOracle.grantRole(daOracle.ATTESTOR_ROLE(), admin);

        // PrivacyZoneManager
        zoneManager.grantRole(zoneManager.DEFAULT_ADMIN_ROLE(), admin);
        zoneManager.grantRole(zoneManager.ZONE_ADMIN_ROLE(), admin);
        zoneManager.grantRole(zoneManager.MIGRATION_OPERATOR_ROLE(), admin);
        zoneManager.grantRole(zoneManager.POLICY_MANAGER_ROLE(), admin);

        // UniversalShieldedPool
        shieldedPool.grantRole(shieldedPool.DEFAULT_ADMIN_ROLE(), admin);
        shieldedPool.grantRole(shieldedPool.OPERATOR_ROLE(), admin);
        shieldedPool.grantRole(shieldedPool.COMPLIANCE_ROLE(), admin);

        // CrossChainPrivacyHub
        privacyHub.grantRole(privacyHub.DEFAULT_ADMIN_ROLE(), admin);
        privacyHub.grantRole(privacyHub.OPERATOR_ROLE(), admin);
        privacyHub.grantRole(privacyHub.RELAYER_ROLE(), admin);
        privacyHub.grantRole(privacyHub.GUARDIAN_ROLE(), admin);
        privacyHub.grantRole(privacyHub.UPGRADER_ROLE(), admin);

        // BatchAccumulator (if deployed)
        if (address(batch) != address(0)) {
            batch.grantRole(batch.DEFAULT_ADMIN_ROLE(), admin);
            batch.grantRole(batch.OPERATOR_ROLE(), admin);
            batch.grantRole(batch.RELAYER_ROLE(), admin);
            batch.grantRole(batch.UPGRADER_ROLE(), admin);
        }

        console.log("All roles granted to multisig:", admin);

        // ─── Phase 7: Renounce Deployer Roles ──────────────────────
        console.log("");
        console.log("--- Phase 7: Renounce Deployer Roles ---");

        // StealthAddressRegistry
        stealth.renounceRole(stealth.ANNOUNCER_ROLE(), deployer);
        stealth.renounceRole(stealth.OPERATOR_ROLE(), deployer);
        stealth.renounceRole(stealth.UPGRADER_ROLE(), deployer);
        stealth.renounceRole(stealth.DEFAULT_ADMIN_ROLE(), deployer);

        // ViewKeyRegistry
        viewKey.renounceRole(viewKey.REGISTRAR_ROLE(), deployer);
        viewKey.renounceRole(viewKey.ADMIN_ROLE(), deployer);
        viewKey.renounceRole(viewKey.DEFAULT_ADMIN_ROLE(), deployer);

        // DataAvailabilityOracle
        daOracle.renounceRole(daOracle.ATTESTOR_ROLE(), deployer);
        daOracle.renounceRole(daOracle.DA_ADMIN_ROLE(), deployer);
        daOracle.renounceRole(daOracle.DEFAULT_ADMIN_ROLE(), deployer);

        // PrivacyZoneManager
        zoneManager.renounceRole(zoneManager.POLICY_MANAGER_ROLE(), deployer);
        zoneManager.renounceRole(
            zoneManager.MIGRATION_OPERATOR_ROLE(),
            deployer
        );
        zoneManager.renounceRole(zoneManager.ZONE_ADMIN_ROLE(), deployer);
        zoneManager.renounceRole(zoneManager.DEFAULT_ADMIN_ROLE(), deployer);

        // UniversalShieldedPool
        shieldedPool.renounceRole(shieldedPool.COMPLIANCE_ROLE(), deployer);
        shieldedPool.renounceRole(shieldedPool.OPERATOR_ROLE(), deployer);
        shieldedPool.renounceRole(relayerRole, deployer);
        shieldedPool.renounceRole(shieldedPool.DEFAULT_ADMIN_ROLE(), deployer);

        // CrossChainPrivacyHub
        privacyHub.renounceRole(privacyHub.GUARDIAN_ROLE(), deployer);
        privacyHub.renounceRole(privacyHub.RELAYER_ROLE(), deployer);
        privacyHub.renounceRole(privacyHub.OPERATOR_ROLE(), deployer);
        privacyHub.renounceRole(privacyHub.UPGRADER_ROLE(), deployer);
        privacyHub.renounceRole(privacyHub.DEFAULT_ADMIN_ROLE(), deployer);

        // BatchAccumulator (if deployed)
        if (address(batch) != address(0)) {
            batch.renounceRole(batch.RELAYER_ROLE(), deployer);
            batch.renounceRole(batch.OPERATOR_ROLE(), deployer);
            batch.renounceRole(batch.UPGRADER_ROLE(), deployer);
            batch.renounceRole(batch.DEFAULT_ADMIN_ROLE(), deployer);
        }

        console.log("All deployer roles renounced for:", deployer);

        vm.stopBroadcast();

        // ─── Summary ───────────────────────────────────────────────
        console.log("");
        console.log("========================================");
        console.log("  Deployment Summary");
        console.log("========================================");
        console.log("StealthAddressRegistry:", address(stealth));
        console.log("ViewKeyRegistry:       ", address(viewKey));
        console.log("DataAvailabilityOracle:", address(daOracle));
        console.log("PrivacyZoneManager:    ", address(zoneManager));
        console.log("ShieldedPool:          ", address(shieldedPool));
        console.log("CrossChainPrivacyHub:  ", address(privacyHub));
        console.log("");
        console.log("POST-DEPLOY REQUIRED:");
        console.log(
            "  1. Wire these into ZaseonProtocolHub via wireAll() or individual setters"
        );
        console.log("  2. Register bridge adapters on CrossChainPrivacyHub");
        console.log("  3. Set derivation verifier on StealthAddressRegistry");
        console.log(
            "  4. Grant ATTESTOR_ROLE on DataAvailabilityOracle to attestors"
        );
        console.log("  5. Configure privacy zones via PrivacyZoneManager");
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _envAddressOr(
        string memory key,
        address fallback_
    ) internal view returns (address) {
        try vm.envAddress(key) returns (address val) {
            return val;
        } catch {
            return fallback_;
        }
    }

    function _envBoolOr(
        string memory key,
        bool fallback_
    ) internal view returns (bool) {
        try vm.envBool(key) returns (bool val) {
            return val;
        } catch {
            return fallback_;
        }
    }
}
