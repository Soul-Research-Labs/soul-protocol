// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ZaseonProtocolHub} from "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";

/**
 * @title WireRemainingComponents
 * @notice Post-deploy script to wire components that were deployed separately
 *         after the initial Hub deployment (Phase 6 of DeployMainnet).
 *
 * @dev The initial mainnet deploy sets 8/17 wireAll params. This script fills
 *      the remaining 9 that are deployed per-L2 or as upgradeable proxies:
 *        - crossChainMessageRelay   (per-L2 ZaseonCrossChainRelay)
 *        - crossChainPrivacyHub     (per-L2 privacy coordination)
 *        - stealthAddressRegistry   (upgradeable)
 *        - privateRelayerNetwork    (DecentralizedRelayerRegistry)
 *        - viewKeyRegistry          (optional)
 *        - shieldedPool             (UniversalShieldedPool)
 *        - complianceOracle         (optional)
 *        - proofTranslator          (optional)
 *        - privacyRouter            (required for isFullyConfigured)
 *        - multiProver              (required for isFullyConfigured)
 *        - relayWatchtower          (required for isFullyConfigured)
 *        - relayCircuitBreaker      (not in wireAll, wired via setter)
 *
 * Usage:
 *   ZASEON_HUB=0x...         \
 *   RELAY=0x...             \
 *   PRIVACY_HUB=0x...       \
 *   STEALTH_REGISTRY=0x...  \
 *   RELAYER_NETWORK=0x...   \
 *   VIEW_KEY_REGISTRY=0x... \
 *   SHIELDED_POOL=0x...     \
 *   COMPLIANCE_ORACLE=0x... \
 *   PROOF_TRANSLATOR=0x...  \
 *   PRIVACY_ROUTER=0x...    \
 *   MULTI_PROVER=0x...       \
 *   RELAY_WATCHTOWER=0x...   \
 *   RELAY_CIRCUIT_BREAKER=0x... \
 *   forge script scripts/deploy/WireRemainingComponents.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify
 *
 * Any env var left unset defaults to address(0) and the Hub skips that field.
 */
contract WireRemainingComponents is Script {
    function run() external {
        address hubAddr = vm.envAddress("ZASEON_HUB");
        require(hubAddr != address(0), "ZASEON_HUB required");

        // Read optional addresses — default to address(0) if not set
        address relay = _envOr("RELAY");
        address privacyHub = _envOr("PRIVACY_HUB");
        address stealthRegistry = _envOr("STEALTH_REGISTRY");
        address relayerNetwork = _envOr("RELAYER_NETWORK");
        address viewKeyRegistry = _envOr("VIEW_KEY_REGISTRY");
        address shieldedPool = _envOr("SHIELDED_POOL");
        address complianceOracle = _envOr("COMPLIANCE_ORACLE");
        address proofTranslator = _envOr("PROOF_TRANSLATOR");
        address privacyRouter = _envOr("PRIVACY_ROUTER");
        address multiProver = _envOr("MULTI_PROVER");
        address relayWatchtower = _envOr("RELAY_WATCHTOWER");
        address relayCircuitBreaker = _envOr("RELAY_CIRCUIT_BREAKER");

        ZaseonProtocolHub hub = ZaseonProtocolHub(hubAddr);

        console.log("=== Wire Remaining Components ===");
        console.log("Hub:                ", hubAddr);
        console.log("Relay:              ", relay);
        console.log("Privacy Hub:        ", privacyHub);
        console.log("Stealth Registry:   ", stealthRegistry);
        console.log("Relayer Network:    ", relayerNetwork);
        console.log("View Key Registry:  ", viewKeyRegistry);
        console.log("Shielded Pool:      ", shieldedPool);
        console.log("Compliance Oracle:  ", complianceOracle);
        console.log("Proof Translator:   ", proofTranslator);
        console.log("Privacy Router:     ", privacyRouter);
        console.log("Multi Prover:       ", multiProver);
        console.log("Relay Watchtower:   ", relayWatchtower);
        console.log("Relay Circuit Breaker:", relayCircuitBreaker);

        vm.startBroadcast();

        // wireAll with zero-address for already-wired components (Hub skips them)
        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0), // already set
                _universalVerifier: address(0), // already set
                _crossChainMessageRelay: relay,
                _crossChainPrivacyHub: privacyHub,
                _stealthAddressRegistry: stealthRegistry,
                _privateRelayerNetwork: relayerNetwork,
                _viewKeyRegistry: viewKeyRegistry,
                _shieldedPool: shieldedPool,
                _nullifierManager: address(0), // already set
                _complianceOracle: complianceOracle,
                _proofTranslator: proofTranslator,
                _privacyRouter: privacyRouter,
                _relayProofValidator: address(0), // already set
                _zkBoundStateLocks: address(0), // already set
                _proofCarryingContainer: address(0), // already set
                _crossDomainNullifierAlgebra: address(0), // already set
                _policyBoundProofs: address(0), // already set
                _multiProver: multiProver,
                _relayWatchtower: relayWatchtower
                _intentCompletionLayer: address(0),
                _instantCompletionGuarantee: address(0),
                _dynamicRoutingOrchestrator: address(0),
                _crossChainLiquidityVault: address(0)
            })
        );

        // Wire relay circuit breaker (not in wireAll struct)
        if (relayCircuitBreaker != address(0)) {
            hub.setRelayCircuitBreaker(relayCircuitBreaker);
            console.log("RelayCircuitBreaker wired to Hub");
        }

        vm.stopBroadcast();

        // Post-check
        bool configured = hub.isFullyConfigured();
        console.log("\nisFullyConfigured:", configured);
        if (!configured) {
            console.log(
                "WARNING: Hub is not yet fully configured.",
                "Ensure shieldedPool and privacyRouter are set."
            );
        } else {
            console.log("Hub is fully configured and operational.");
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
