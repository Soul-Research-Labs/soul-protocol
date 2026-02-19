// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {DynamicRoutingOrchestrator} from "../../contracts/core/DynamicRoutingOrchestrator.sol";
import {LiquidityAwareRouter} from "../../contracts/bridge/LiquidityAwareRouter.sol";

/**
 * @title DeployRoutingSuite
 * @notice Deploys the Phase 4 Dynamic Routing & Liquidity suite:
 *         DynamicRoutingOrchestrator, LiquidityAwareRouter
 * @dev Usage:
 *   forge script scripts/deploy/DeployRoutingSuite.s.sol:DeployRoutingSuite \
 *     --rpc-url $RPC_URL --broadcast --verify
 *
 *   Environment variables:
 *     DEPLOYER_PRIVATE_KEY   - Deployer private key
 *     ROUTING_ADMIN          - Admin address (defaults to deployer)
 *     ROUTING_ORACLE         - Oracle address for liquidity updates (defaults to deployer)
 *     ROUTING_BRIDGE_ADMIN   - Bridge admin address (defaults to deployer)
 *     ROUTING_EXECUTOR       - Router executor address (defaults to deployer)
 */
contract DeployRoutingSuite is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);
        address admin = vm.envOr("ROUTING_ADMIN", deployer);
        address oracle = vm.envOr("ROUTING_ORACLE", deployer);
        address bridgeAdmin = vm.envOr("ROUTING_BRIDGE_ADMIN", deployer);
        address executor = vm.envOr("ROUTING_EXECUTOR", deployer);

        console.log("=== Soul Protocol Routing Suite Deployment ===");
        console.log("Deployer:", deployer);
        console.log("Admin:", admin);
        console.log("Oracle:", oracle);
        console.log("Bridge Admin:", bridgeAdmin);
        console.log("Executor:", executor);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPk);

        // 1. Deploy DynamicRoutingOrchestrator
        DynamicRoutingOrchestrator orchestrator = new DynamicRoutingOrchestrator(
                admin,
                oracle,
                bridgeAdmin
            );
        console.log("DynamicRoutingOrchestrator:", address(orchestrator));

        // 2. Deploy LiquidityAwareRouter
        LiquidityAwareRouter router = new LiquidityAwareRouter(
            address(orchestrator),
            admin,
            executor
        );
        console.log("LiquidityAwareRouter:", address(router));

        // 3. Grant ROUTER_ROLE to LiquidityAwareRouter on orchestrator
        orchestrator.grantRole(orchestrator.ROUTER_ROLE(), address(router));
        console.log("  Granted ROUTER_ROLE to LiquidityAwareRouter");

        // 4. Register default liquidity pools for supported L2 networks
        orchestrator.registerPool(1, 0, 0.01 ether); // Ethereum
        orchestrator.registerPool(42161, 0, 0.005 ether); // Arbitrum
        orchestrator.registerPool(10, 0, 0.005 ether); // Optimism
        orchestrator.registerPool(8453, 0, 0.005 ether); // Base
        orchestrator.registerPool(324, 0, 0.008 ether); // zkSync
        orchestrator.registerPool(534352, 0, 0.008 ether); // Scroll
        orchestrator.registerPool(59144, 0, 0.008 ether); // Linea
        orchestrator.registerPool(1101, 0, 0.008 ether); // Polygon zkEVM
        console.log("  Registered 8 liquidity pools");

        vm.stopBroadcast();

        // Save deployment addresses
        string memory json = string.concat(
            "{\n",
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "deployer": "',
            vm.toString(deployer),
            '",\n',
            '  "admin": "',
            vm.toString(admin),
            '",\n',
            '  "oracle": "',
            vm.toString(oracle),
            '",\n',
            '  "bridgeAdmin": "',
            vm.toString(bridgeAdmin),
            '",\n',
            '  "executor": "',
            vm.toString(executor),
            '",\n',
            '  "DynamicRoutingOrchestrator": "',
            vm.toString(address(orchestrator)),
            '",\n',
            '  "LiquidityAwareRouter": "',
            vm.toString(address(router)),
            '"\n}'
        );
        vm.writeFile(
            string.concat(
                "deployments/routing-",
                vm.toString(block.chainid),
                ".json"
            ),
            json
        );

        console.log("");
        console.log("=== Deployment Complete ===");
        console.log(
            "Deployment manifest written to deployments/routing-<chainId>.json"
        );
    }
}

/**
 * @title DeployRoutingSuiteTestnet
 * @notice Testnet deployment with sample bridge registration for testing
 */
contract DeployRoutingSuiteTestnet is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        console.log("=== Soul Protocol Routing Suite (Testnet) ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("");

        vm.startBroadcast(deployerPk);

        // Deploy with deployer as all roles (testnet convenience)
        DynamicRoutingOrchestrator orchestrator = new DynamicRoutingOrchestrator(
                deployer,
                deployer,
                deployer
            );
        console.log("DynamicRoutingOrchestrator:", address(orchestrator));

        LiquidityAwareRouter router = new LiquidityAwareRouter(
            address(orchestrator),
            deployer,
            deployer
        );
        console.log("LiquidityAwareRouter:", address(router));

        // Grant ROUTER_ROLE to router
        orchestrator.grantRole(orchestrator.ROUTER_ROLE(), address(router));

        // Register testnet pools (Sepolia + testnets)
        orchestrator.registerPool(11155111, 100 ether, 0.001 ether); // Sepolia
        orchestrator.registerPool(421614, 100 ether, 0.001 ether); // Arb Sepolia
        orchestrator.registerPool(11155420, 100 ether, 0.001 ether); // OP Sepolia
        orchestrator.registerPool(84532, 100 ether, 0.001 ether); // Base Sepolia
        console.log("  Registered 4 testnet pools");

        vm.stopBroadcast();

        console.log("");
        console.log("=== Testnet Deployment Complete ===");
    }
}
