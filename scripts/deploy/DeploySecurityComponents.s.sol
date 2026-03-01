// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ProtocolHealthAggregator} from "../../contracts/security/ProtocolHealthAggregator.sol";
import {EmergencyRecovery} from "../../contracts/security/EmergencyRecovery.sol";
import {ProtocolEmergencyCoordinator} from "../../contracts/security/ProtocolEmergencyCoordinator.sol";
import {CrossChainEmergencyRelay} from "../../contracts/crosschain/CrossChainEmergencyRelay.sol";
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import {IZaseonProtocolHub} from "../../contracts/interfaces/IZaseonProtocolHub.sol";

/**
 * @title DeploySecurityComponents
 * @notice Deploys and wires the security/emergency subsystem that was missing
 *         from the initial DeployMainnet.s.sol phases.
 *
 * @dev Deploys:
 *      1. ProtocolHealthAggregator  — composite health scoring
 *      2. EmergencyRecovery         — recovery executor
 *      3. ProtocolEmergencyCoordinator — multi-role emergency coordination
 *      4. CrossChainEmergencyRelay  — cross-chain emergency propagation
 *
 * Prerequisites (from Phase 1 of DeployMainnet):
 *      - ZaseonProtocolHub  is deployed and admin owns DEFAULT_ADMIN_ROLE
 *      - EnhancedKillSwitch is deployed
 *      - RelayCircuitBreaker is deployed
 *      - RelayWatchtower is deployed (or will be set later)
 *
 * Usage:
 *   ZASEON_HUB=0x...          \
 *   KILL_SWITCH=0x...       \
 *   CIRCUIT_BREAKER=0x...   \
 *   RELAY_WATCHTOWER=0x...  \
 *   MULTI_PROVER=0x...      \
 *   forge script scripts/deploy/DeploySecurityComponents.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify
 */
contract DeploySecurityComponents is Script {
    uint16 constant HEALTHY_THRESHOLD = 70;
    uint16 constant CRITICAL_THRESHOLD = 40;

    function run() external {
        address hubAddr = vm.envAddress("ZASEON_HUB");
        address killSwitch = vm.envAddress("KILL_SWITCH");
        address circuitBreaker = vm.envAddress("CIRCUIT_BREAKER");
        address relayWatchtower = _envOr("RELAY_WATCHTOWER");
        address multiProver = _envOr("MULTI_PROVER");
        address admin = msg.sender;

        require(hubAddr != address(0), "ZASEON_HUB required");
        require(killSwitch != address(0), "KILL_SWITCH required");
        require(circuitBreaker != address(0), "CIRCUIT_BREAKER required");

        ZaseonProtocolHub hub = ZaseonProtocolHub(hubAddr);

        console.log("=== Deploy Security Components ===");
        console.log("Hub:              ", hubAddr);
        console.log("KillSwitch:       ", killSwitch);
        console.log("CircuitBreaker:   ", circuitBreaker);
        console.log("Admin:            ", admin);

        vm.startBroadcast();

        // 1. ProtocolHealthAggregator
        ProtocolHealthAggregator healthAggregator = new ProtocolHealthAggregator(
                admin,
                HEALTHY_THRESHOLD,
                CRITICAL_THRESHOLD
            );
        console.log("ProtocolHealthAggregator:", address(healthAggregator));

        // 2. EmergencyRecovery
        EmergencyRecovery emergencyRecovery = new EmergencyRecovery();
        console.log("EmergencyRecovery:", address(emergencyRecovery));

        // 3. ProtocolEmergencyCoordinator (ties everything together)
        ProtocolEmergencyCoordinator coordinator = new ProtocolEmergencyCoordinator(
                address(healthAggregator),
                address(emergencyRecovery),
                killSwitch,
                circuitBreaker,
                hubAddr,
                admin
            );
        console.log("ProtocolEmergencyCoordinator:", address(coordinator));

        // 4. CrossChainEmergencyRelay
        CrossChainEmergencyRelay emergencyRelay = new CrossChainEmergencyRelay(
            admin
        );
        console.log("CrossChainEmergencyRelay:", address(emergencyRelay));

        // 5. Wire watchtower + multiProver into Hub (via wireAll for the two missing fields)
        if (relayWatchtower != address(0) || multiProver != address(0)) {
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
                    _multiProver: multiProver,
                    _relayWatchtower: relayWatchtower,
                    _intentCompletionLayer: address(0),
                    _instantCompletionGuarantee: address(0),
                    _dynamicRoutingOrchestrator: address(0),
                    _crossChainLiquidityVault: address(0)
                })
            );
            console.log("Hub wired: multiProver + relayWatchtower");
        }

        // 6. Wire circuit breaker (individual setter, not in wireAll)
        hub.setRelayCircuitBreaker(circuitBreaker);
        console.log("RelayCircuitBreaker wired to Hub");

        vm.stopBroadcast();

        // Post-check
        bool configured = hub.isFullyConfigured();
        console.log("\nisFullyConfigured:", configured);
        if (!configured) {
            console.log(
                "NOTE: Hub still not fully configured.",
                "Ensure multiProver & relayWatchtower are set."
            );
        }

        console.log("\n=== Security Components Deployed ===");
        console.log("Next steps:");
        console.log(
            "  1. Grant GUARDIAN/RESPONDER/RECOVERY roles to separate multisigs"
        );
        console.log("  2. Call coordinator.confirmRoleSeparation()");
        console.log("  3. Register L2 chains on CrossChainEmergencyRelay");
        console.log("  4. Set emergency relay bridge adapters");
    }

    function _envOr(string memory key) internal view returns (address) {
        try vm.envAddress(key) returns (address val) {
            return val;
        } catch {
            return address(0);
        }
    }
}
