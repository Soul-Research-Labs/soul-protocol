// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../contracts/security/ExperimentalFeatureRegistry.sol";
import "../../contracts/bridge/MultiBridgeRouter.sol";
import "../../contracts/security/OptimisticRelayVerifier.sol";

/**
 * @title DeployRiskMitigation
 * @notice Deployment script for Phase 1 risk mitigation contracts
 * @dev Deploys:
 *      1. ExperimentalFeatureRegistry - Disable experimental features
 *      2. MultiBridgeRouter - Bridge diversity and fallback
 *      3. OptimisticRelayVerifier - Challenge periods for high-value transfers
 */
contract DeployRiskMitigation is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying Risk Mitigation Contracts...");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy ExperimentalFeatureRegistry
        console.log("\n1. Deploying ExperimentalFeatureRegistry...");
        ExperimentalFeatureRegistry featureRegistry = new ExperimentalFeatureRegistry(
                deployer
            );
        console.log(
            "ExperimentalFeatureRegistry deployed at:",
            address(featureRegistry)
        );
        console.log("- FHE_OPERATIONS: DISABLED (max 1 ETH)");
        console.log("- PQC_SIGNATURES: DISABLED (max 0.1 ETH)");
        console.log("- MPC_THRESHOLD: DISABLED (max 0.5 ETH)");

        // 2. Deploy MultiBridgeRouter
        console.log("\n2. Deploying MultiBridgeRouter...");
        MultiBridgeRouter bridgeRouter = new MultiBridgeRouter(deployer);
        console.log("MultiBridgeRouter deployed at:", address(bridgeRouter));
        console.log(
            "- Supports: Native L2, LayerZero, Hyperlane, Chainlink CCIP, Axelar"
        );
        console.log("- High value threshold: 100 ETH");
        console.log("- Multi-verification threshold: 50 ETH");

        // 3. Deploy OptimisticRelayVerifier
        console.log("\n3. Deploying OptimisticRelayVerifier...");
        OptimisticRelayVerifier optimisticVerifier = new OptimisticRelayVerifier(
                deployer
            );
        console.log(
            "OptimisticRelayVerifier deployed at:",
            address(optimisticVerifier)
        );
        console.log("- Challenge period: 1 hour");
        console.log("- Optimistic threshold: 10 ETH");
        console.log("- Min challenge bond: 0.01 ETH");

        vm.stopBroadcast();

        // Save deployment addresses
        string memory deployments = string(
            abi.encodePacked(
                "# Risk Mitigation Deployment\n",
                "Chain ID: ",
                vm.toString(block.chainid),
                "\n",
                "Deployer: ",
                vm.toString(deployer),
                "\n\n",
                "## Contracts\n",
                "ExperimentalFeatureRegistry: ",
                vm.toString(address(featureRegistry)),
                "\n",
                "MultiBridgeRouter: ",
                vm.toString(address(bridgeRouter)),
                "\n",
                "OptimisticRelayVerifier: ",
                vm.toString(address(optimisticVerifier)),
                "\n"
            )
        );

        vm.writeFile("deployments/risk-mitigation.txt", deployments);

        console.log("\n=== Deployment Complete ===");
        console.log(
            "Deployment info saved to: deployments/risk-mitigation.txt"
        );
        console.log("\nNext Steps:");
        console.log("1. Verify contracts on block explorer");
        console.log("2. Configure bridge adapters in MultiBridgeRouter");
        console.log("3. Integrate with existing ZASEON contracts");
        console.log("4. Run integration tests");
        console.log("5. Update documentation");
    }
}
