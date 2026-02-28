// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";
import "../../contracts/relayer/HeterogeneousRelayerRegistry.sol";
import "../../contracts/relayer/RelayerHealthMonitor.sol";
import "../../contracts/relayer/RelayerStaking.sol";
import "../../contracts/relayer/RelayerFeeMarket.sol";
import "../../contracts/relayer/RelayerSLAEnforcer.sol";
import "../../contracts/relayer/InstantRelayerRewards.sol";
import "../../contracts/relayer/MultiRelayerRouter.sol";
import "../../contracts/relayer/GelatoRelayAdapter.sol";
import "../../contracts/relayer/SelfRelayAdapter.sol";

/**
 * @title DeployRelayerInfrastructure
 * @notice Deploys the full relayer infrastructure stack for ZASEON.
 *
 * @dev Deployment order is dependency-aware:
 *   Phase 1 — Core Registries (no cross-contract deps)
 *   Phase 2 — Staking & Economics (standalone)
 *   Phase 3 — Monitoring & SLA (standalone)
 *   Phase 4 — Adapters (depend on HealthMonitor)
 *   Phase 5 — Router (depends on adapters)
 *   Phase 6 — Cross-contract wiring (roles, references)
 *
 * Environment Variables:
 *   PRIVATE_KEY         — Deployer private key (required)
 *   STAKING_TOKEN       — ERC-20 token address for RelayerStaking (required)
 *   FEE_TOKEN           — ERC-20 token address for RelayerFeeMarket (required)
 *   GELATO_RELAY        — Gelato Relay contract address (optional; skips GelatoRelayAdapter if unset)
 *   MIN_STAKE           — Minimum stake for RelayerStaking in wei (optional; default 1 ether)
 *
 * Usage (dry-run):
 *   forge script scripts/deploy/DeployRelayerInfrastructure.s.sol \
 *     --rpc-url $RPC_URL -vvv
 *
 * Usage (broadcast):
 *   forge script scripts/deploy/DeployRelayerInfrastructure.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify -vvv
 */
contract DeployRelayerInfrastructure is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        address stakingToken = vm.envAddress("STAKING_TOKEN");
        address feeToken = vm.envAddress("FEE_TOKEN");
        uint256 minStake = _envUintOr("MIN_STAKE", 1 ether);
        address gelatoRelay = _envAddressOr("GELATO_RELAY");

        console.log("========================================");
        console.log("  Deploy Relayer Infrastructure");
        console.log("========================================");
        console.log("Deployer:      ", deployer);
        console.log("Chain ID:      ", block.chainid);
        console.log("Staking Token: ", stakingToken);
        console.log("Fee Token:     ", feeToken);
        console.log("Min Stake:     ", minStake);
        console.log("Gelato Relay:  ", gelatoRelay);
        console.log("");

        vm.startBroadcast(deployerPrivateKey);

        // =============================================
        // Phase 1: Core Registries
        // =============================================
        console.log("--- Phase 1: Core Registries ---");

        DecentralizedRelayerRegistry decentralizedRegistry = new DecentralizedRelayerRegistry(
                deployer
            );
        console.log(
            "DecentralizedRelayerRegistry:",
            address(decentralizedRegistry)
        );

        HeterogeneousRelayerRegistry heteroRegistry = new HeterogeneousRelayerRegistry(
                deployer
            );
        console.log("HeterogeneousRelayerRegistry:", address(heteroRegistry));

        // =============================================
        // Phase 2: Staking & Economics
        // =============================================
        console.log("--- Phase 2: Staking & Economics ---");

        RelayerStaking staking = new RelayerStaking(
            stakingToken,
            minStake,
            deployer
        );
        console.log("RelayerStaking:              ", address(staking));

        RelayerFeeMarket feeMarket = new RelayerFeeMarket(deployer, feeToken);
        console.log("RelayerFeeMarket:            ", address(feeMarket));

        InstantRelayerRewards instantRewards = new InstantRelayerRewards(
            deployer
        );
        console.log("InstantRelayerRewards:       ", address(instantRewards));

        // =============================================
        // Phase 3: Monitoring & SLA
        // =============================================
        console.log("--- Phase 3: Monitoring & SLA ---");

        RelayerHealthMonitor healthMonitor = new RelayerHealthMonitor(deployer);
        console.log("RelayerHealthMonitor:        ", address(healthMonitor));

        RelayerSLAEnforcer slaEnforcer = new RelayerSLAEnforcer(deployer);
        console.log("RelayerSLAEnforcer:          ", address(slaEnforcer));

        // =============================================
        // Phase 4: Relay Adapters
        // =============================================
        console.log("--- Phase 4: Relay Adapters ---");

        SelfRelayAdapter selfRelay = new SelfRelayAdapter(
            deployer,
            address(healthMonitor)
        );
        console.log("SelfRelayAdapter:            ", address(selfRelay));

        address gelatoAdapterAddr = address(0);
        if (gelatoRelay != address(0)) {
            GelatoRelayAdapter gelatoAdapter = new GelatoRelayAdapter(
                gelatoRelay
            );
            gelatoAdapterAddr = address(gelatoAdapter);
            console.log("GelatoRelayAdapter:          ", gelatoAdapterAddr);
        } else {
            console.log(
                "GelatoRelayAdapter:           SKIPPED (GELATO_RELAY not set)"
            );
        }

        // =============================================
        // Phase 5: Multi-Relayer Router
        // =============================================
        console.log("--- Phase 5: Multi-Relayer Router ---");

        MultiRelayerRouter router = new MultiRelayerRouter(deployer);
        console.log("MultiRelayerRouter:          ", address(router));

        // =============================================
        // Phase 6: Cross-Contract Wiring
        // =============================================
        console.log("--- Phase 6: Cross-Contract Wiring ---");

        // Grant ROUTER_ROLE on HealthMonitor to the MultiRelayerRouter
        healthMonitor.grantRole(healthMonitor.ROUTER_ROLE(), address(router));
        console.log("  HealthMonitor: granted ROUTER_ROLE -> Router");

        // Grant ROUTER_ROLE on HealthMonitor to SelfRelayAdapter (it reports stats)
        healthMonitor.grantRole(
            healthMonitor.ROUTER_ROLE(),
            address(selfRelay)
        );
        console.log("  HealthMonitor: granted ROUTER_ROLE -> SelfRelay");

        // Grant RELAY_MANAGER_ROLE on InstantRewards to the Router
        instantRewards.grantRole(
            instantRewards.RELAY_MANAGER_ROLE(),
            address(router)
        );
        console.log("  InstantRewards: granted RELAY_MANAGER_ROLE -> Router");

        // Grant REPORTER_ROLE on SLAEnforcer to the Router and HealthMonitor
        slaEnforcer.grantRole(slaEnforcer.REPORTER_ROLE(), address(router));
        console.log("  SLAEnforcer: granted REPORTER_ROLE -> Router");

        slaEnforcer.grantRole(
            slaEnforcer.REPORTER_ROLE(),
            address(healthMonitor)
        );
        console.log("  SLAEnforcer: granted REPORTER_ROLE -> HealthMonitor");

        // Grant SLASHER_ROLE on DecentralizedRegistry to the SLAEnforcer
        decentralizedRegistry.grantRole(
            decentralizedRegistry.SLASHER_ROLE(),
            address(slaEnforcer)
        );
        console.log(
            "  DecentralizedRegistry: granted SLASHER_ROLE -> SLAEnforcer"
        );

        vm.stopBroadcast();

        // =============================================
        // Summary
        // =============================================
        console.log("");
        console.log("=== Deployed Relayer Infrastructure ===");
        console.log(
            "DecentralizedRelayerRegistry:",
            address(decentralizedRegistry)
        );
        console.log("HeterogeneousRelayerRegistry:", address(heteroRegistry));
        console.log("RelayerStaking:              ", address(staking));
        console.log("RelayerFeeMarket:            ", address(feeMarket));
        console.log("InstantRelayerRewards:       ", address(instantRewards));
        console.log("RelayerHealthMonitor:        ", address(healthMonitor));
        console.log("RelayerSLAEnforcer:          ", address(slaEnforcer));
        console.log("SelfRelayAdapter:            ", address(selfRelay));
        console.log("GelatoRelayAdapter:          ", gelatoAdapterAddr);
        console.log("MultiRelayerRouter:          ", address(router));
        console.log("");
        console.log("Next steps:");
        console.log(
            "  1. Register adapters on MultiRelayerRouter (SelfRelay, Gelato)"
        );
        console.log(
            "  2. Wire DecentralizedRelayerRegistry into ZaseonProtocolHub via"
        );
        console.log("     WireRemainingComponents (RELAYER_NETWORK env var)");
        console.log("  3. Fund RelayerStaking reward pool");
        console.log(
            "  4. Register initial relayers on DecentralizedRelayerRegistry"
        );
        console.log("  5. Verify all contracts on block explorer");
    }

    /// @dev Read an address from env, returning address(0) if not set.
    function _envAddressOr(string memory key) internal view returns (address) {
        try vm.envAddress(key) returns (address val) {
            return val;
        } catch {
            return address(0);
        }
    }

    /// @dev Read a uint256 from env, returning a default if not set.
    function _envUintOr(
        string memory key,
        uint256 defaultVal
    ) internal view returns (uint256) {
        try vm.envUint(key) returns (uint256 val) {
            return val;
        } catch {
            return defaultVal;
        }
    }
}
