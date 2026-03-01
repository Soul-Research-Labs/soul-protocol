// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";
import {IntentCompletionLayer} from "../../contracts/core/IntentCompletionLayer.sol";
import {InstantCompletionGuarantee} from "../../contracts/core/InstantCompletionGuarantee.sol";
import {DynamicRoutingOrchestrator} from "../../contracts/core/DynamicRoutingOrchestrator.sol";

/**
 * @title WireIntentComponents
 * @notice Deploy and wire the Tachyon-inspired intent suite into the ZaseonProtocolHub.
 *
 * @dev Deploys three contracts in dependency order:
 *      1. IntentCompletionLayer   — intent-based cross-chain completion
 *      2. InstantCompletionGuarantee — bonded proof delivery guarantees
 *      3. DynamicRoutingOrchestrator — multi-bridge routing with ML-style scoring
 *
 *      Then wires all three into the Hub via wireAll (zero-address for existing components).
 *
 * Required env vars:
 *   ZASEON_HUB           — Existing Hub address
 *   ADMIN              — Admin address for all three contracts
 *   ORACLE             — Oracle address for DynamicRoutingOrchestrator
 *   BRIDGE_ADMIN       — Bridge admin for DynamicRoutingOrchestrator
 *
 * Optional env vars:
 *   INTENT_VERIFIER    — ZK verifier for IntentCompletionLayer (default: address(0), set later)
 *
 * Usage:
 *   ZASEON_HUB=0x...       \
 *   ADMIN=0x...           \
 *   ORACLE=0x...          \
 *   BRIDGE_ADMIN=0x...    \
 *   forge script scripts/deploy/WireIntentComponents.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify
 */
contract WireIntentComponents is Script {
    function run() external {
        address hubAddr = vm.envAddress("ZASEON_HUB");
        require(hubAddr != address(0), "ZASEON_HUB required");

        address admin = vm.envAddress("ADMIN");
        require(admin != address(0), "ADMIN required");

        address oracle = vm.envAddress("ORACLE");
        require(oracle != address(0), "ORACLE required");

        address bridgeAdmin = vm.envAddress("BRIDGE_ADMIN");
        require(bridgeAdmin != address(0), "BRIDGE_ADMIN required");

        address intentVerifier = _envOr("INTENT_VERIFIER");

        ZaseonProtocolHub hub = ZaseonProtocolHub(hubAddr);

        console.log("=== Deploy & Wire Intent Components ===");
        console.log("Hub:              ", hubAddr);
        console.log("Admin:            ", admin);
        console.log("Oracle:           ", oracle);
        console.log("Bridge Admin:     ", bridgeAdmin);
        console.log("Intent Verifier:  ", intentVerifier);

        vm.startBroadcast();

        // 1. Deploy IntentCompletionLayer
        IntentCompletionLayer intentLayer = new IntentCompletionLayer(
            admin,
            intentVerifier
        );
        console.log("IntentCompletionLayer deployed at:", address(intentLayer));

        // 2. Deploy InstantCompletionGuarantee (depends on IntentCompletionLayer)
        InstantCompletionGuarantee guarantee = new InstantCompletionGuarantee(
            admin,
            address(intentLayer)
        );
        console.log(
            "InstantCompletionGuarantee deployed at:",
            address(guarantee)
        );

        // 3. Deploy DynamicRoutingOrchestrator (independent)
        DynamicRoutingOrchestrator router = new DynamicRoutingOrchestrator(
            admin,
            oracle,
            bridgeAdmin
        );
        console.log("DynamicRoutingOrchestrator deployed at:", address(router));

        // 4. Wire all three into the Hub (zero-address for pre-existing components)
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
                _intentCompletionLayer: address(intentLayer),
                _instantCompletionGuarantee: address(guarantee),
                _dynamicRoutingOrchestrator: address(router),
                _crossChainLiquidityVault: address(0)
            })
        );

        vm.stopBroadcast();

        // Post-deploy summary
        console.log("\n=== Deployment Summary ===");
        console.log("IntentCompletionLayer:      ", address(intentLayer));
        console.log("InstantCompletionGuarantee: ", address(guarantee));
        console.log("DynamicRoutingOrchestrator: ", address(router));
        console.log("Hub fully configured:       ", hub.isFullyConfigured());

        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();
        console.log("\nHub components wired: %d", names.length);
        for (uint256 i = 0; i < names.length; i++) {
            if (addrs[i] != address(0)) {
                console.log("  [OK]", names[i], addrs[i]);
            }
        }
    }

    /// @dev Read an address from env, returning address(0) if not set.
    function _envOr(string memory key) internal view returns (address) {
        try vm.envAddress(key) returns (address val) {
            return val;
        } catch {
            return address(0);
        }
    }
}
