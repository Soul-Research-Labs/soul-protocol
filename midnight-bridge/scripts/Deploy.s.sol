// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {MidnightBridgeHub} from "../contracts/MidnightBridgeHub.sol";
import {MidnightProofVerifier} from "../contracts/MidnightProofVerifier.sol";
import {MidnightL2BridgeAdapter} from "../contracts/adapters/MidnightL2BridgeAdapter.sol";

/**
 * @title Midnight Bridge Deployment Script
 * @notice Deploys all bridge contracts to the target network
 */
contract DeployScript is Script {
    // Deployment addresses
    address public verifier;
    address public bridgeHub;
    address public l2Adapter;

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console2.log("Deploying from:", deployer);
        console2.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Proof Verifier
        MidnightProofVerifier proofVerifier = new MidnightProofVerifier();
        verifier = address(proofVerifier);
        console2.log("MidnightProofVerifier deployed at:", verifier);

        // 2. Deploy Bridge Hub
        MidnightBridgeHub hub = new MidnightBridgeHub(verifier);
        bridgeHub = address(hub);
        console2.log("MidnightBridgeHub deployed at:", bridgeHub);

        // 3. Deploy L2 Adapter (only on L2s)
        if (isL2Chain(block.chainid)) {
            MidnightL2BridgeAdapter adapter = new MidnightL2BridgeAdapter(
                bridgeHub,
                verifier
            );
            l2Adapter = address(adapter);
            console2.log("MidnightL2BridgeAdapter deployed at:", l2Adapter);
        }

        // 4. Configure Bridge Hub
        // Whitelist common tokens (USDC, USDT, WETH)
        _configureWhitelist(hub);

        vm.stopBroadcast();

        // Log deployment summary
        _logDeploymentSummary();
    }

    function isL2Chain(uint256 chainId) internal pure returns (bool) {
        return
            chainId == 42161 || // Arbitrum
            chainId == 421614 || // Arbitrum Sepolia
            chainId == 10 || // Optimism
            chainId == 8453 || // Base
            chainId == 324 || // zkSync Era
            chainId == 534352 || // Scroll
            chainId == 59144 || // Linea
            chainId == 1101; // Polygon zkEVM
    }

    function _configureWhitelist(MidnightBridgeHub hub) internal {
        // Common token addresses vary by chain
        if (block.chainid == 1) {
            // Mainnet
            hub.whitelistAsset(
                0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,
                true
            ); // USDC
            hub.whitelistAsset(
                0xdAC17F958D2ee523a2206206994597C13D831ec7,
                true
            ); // USDT
            hub.whitelistAsset(
                0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2,
                true
            ); // WETH
        } else if (block.chainid == 42161) {
            // Arbitrum
            hub.whitelistAsset(
                0xaf88d065e77c8cC2239327C5EDb3A432268e5831,
                true
            ); // USDC
            hub.whitelistAsset(
                0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9,
                true
            ); // USDT
            hub.whitelistAsset(
                0x82aF49447D8a07e3bd95BD0d56f35241523fBab1,
                true
            ); // WETH
        } else if (block.chainid == 10) {
            // Optimism
            hub.whitelistAsset(
                0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85,
                true
            ); // USDC
            hub.whitelistAsset(
                0x94b008aA00579c1307B0EF2c499aD98a8ce58e58,
                true
            ); // USDT
            hub.whitelistAsset(
                0x4200000000000000000000000000000000000006,
                true
            ); // WETH
        } else if (block.chainid == 8453) {
            // Base
            hub.whitelistAsset(
                0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,
                true
            ); // USDC
            hub.whitelistAsset(
                0x4200000000000000000000000000000000000006,
                true
            ); // WETH
        }
        // Add more chains as needed
    }

    function _logDeploymentSummary() internal view {
        console2.log("\n========================================");
        console2.log("DEPLOYMENT SUMMARY");
        console2.log("========================================");
        console2.log("Chain ID:              ", block.chainid);
        console2.log("MidnightProofVerifier: ", verifier);
        console2.log("MidnightBridgeHub:     ", bridgeHub);
        if (l2Adapter != address(0)) {
            console2.log("MidnightL2BridgeAdapter:", l2Adapter);
        }
        console2.log("========================================\n");
    }
}

/**
 * @title Upgrade Script
 * @notice Upgrades bridge contracts (for future use with proxies)
 */
contract UpgradeScript is Script {
    function run() public {
        // Future: Implement upgrade logic for proxy patterns
        console2.log("Upgrade functionality not yet implemented");
    }
}

/**
 * @title Configure Script
 * @notice Post-deployment configuration
 */
contract ConfigureScript is Script {
    function run() public {
        address bridgeHubAddress = vm.envAddress("BRIDGE_HUB_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        MidnightBridgeHub hub = MidnightBridgeHub(payable(bridgeHubAddress));

        // Additional configuration as needed
        console2.log("Configuration complete for:", bridgeHubAddress);

        vm.stopBroadcast();
    }
}
