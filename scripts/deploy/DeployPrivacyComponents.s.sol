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
 * @notice Deploys the full privacy middleware stack for Soul Protocol.
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
            BatchAccumulator batch = BatchAccumulator(address(batchProxy));
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
            "  1. Wire these into SoulProtocolHub via wireAll() or individual setters"
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
