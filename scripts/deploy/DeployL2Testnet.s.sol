// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

// Core contracts
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {ConfidentialStateContainerV3} from "../../contracts/core/ConfidentialStateContainerV3.sol";

// Bridge adapters
import {OptimismBridgeAdapter} from "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import {ArbitrumBridgeAdapter} from "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";
import {BaseBridgeAdapter} from "../../contracts/crosschain/BaseBridgeAdapter.sol";
import {ScrollBridgeAdapter} from "../../contracts/experimental/adapters/ScrollBridgeAdapter.sol";
import {LineaBridgeAdapter} from "../../contracts/experimental/adapters/LineaBridgeAdapter.sol";

// Security
import {BridgeCircuitBreaker} from "../../contracts/security/BridgeCircuitBreaker.sol";
import {BridgeRateLimiter} from "../../contracts/security/BridgeRateLimiter.sol";

// Privacy
import {StealthAddressRegistry} from "../../contracts/privacy/StealthAddressRegistry.sol";

/**
 * @title Soul Protocol L2 Testnet Deployment Script
 * @notice Unified Foundry script for deploying to L2 testnets
 *
 * Supported testnets:
 *   - Arbitrum Sepolia  (chain ID 421614)
 *   - Base Sepolia      (chain ID 84532)
 *   - Optimism Sepolia  (chain ID 11155420)
 *   - Scroll Sepolia    (chain ID 534351)
 *   - Linea Sepolia     (chain ID 59141)
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY  - Deployer EOA private key
 *   TESTNET_ADMIN         - Admin address (can be deployer on testnets)
 *   L1_PROOF_HUB          - CrossChainProofHubV3 on Sepolia (optional)
 *
 * Usage:
 *   # Arbitrum Sepolia
 *   forge script scripts/deploy/DeployL2Testnet.s.sol \
 *     --rpc-url $ARBITRUM_SEPOLIA_RPC_URL \
 *     --broadcast --verify \
 *     --etherscan-api-key $ARBISCAN_API_KEY \
 *     -vvv
 *
 *   # Base Sepolia
 *   forge script scripts/deploy/DeployL2Testnet.s.sol \
 *     --rpc-url $BASE_SEPOLIA_RPC_URL \
 *     --broadcast --verify \
 *     --etherscan-api-key $BASESCAN_API_KEY \
 *     -vvv
 *
 *   # Dry run (simulation only)
 *   forge script scripts/deploy/DeployL2Testnet.s.sol \
 *     --rpc-url $OPTIMISM_SEPOLIA_RPC_URL -vvv
 */
contract DeployL2Testnet is Script {
    // ========= TESTNET CHAIN IDs =========
    uint256 constant ARBITRUM_SEPOLIA = 421614;
    uint256 constant BASE_SEPOLIA = 84532;
    uint256 constant OPTIMISM_SEPOLIA = 11155420;
    uint256 constant SCROLL_SEPOLIA = 534351;
    uint256 constant LINEA_SEPOLIA = 59141;
    uint256 constant L1_SEPOLIA = 11155111;

    // ========= TESTNET CONFIGURATION =========
    // Relaxed parameters for testing
    uint256 constant MAX_PROOFS_PER_HOUR = 10000;
    uint256 constant MAX_VALUE_PER_HOUR = 10000 ether;

    // Deployed contract addresses (set during deployment)
    NullifierRegistryV3 public nullifierRegistry;
    BridgeCircuitBreaker public circuitBreaker;
    BridgeRateLimiter public rateLimiter;
    StealthAddressRegistry public stealthRegistry;
    address public bridgeAdapter;

    function run() external {
        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);
        // On testnets, admin can be the deployer for simplicity
        address admin = vm.envOr("TESTNET_ADMIN", deployer);

        console.log("=== Soul Protocol L2 Testnet Deployment ===");
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", deployer);
        console.log("Admin:", admin);

        _validateChainId();

        vm.startBroadcast(deployerPK);

        // ========= 1. DEPLOY CORE CONTRACTS =========
        _deployCoreContracts(admin);

        // ========= 2. DEPLOY CHAIN-SPECIFIC BRIDGE =========
        _deployBridgeAdapter(admin, deployer);

        // ========= 3. DEPLOY PRIVACY CONTRACTS =========
        _deployPrivacyContracts(admin);

        // ========= 4. CONFIGURE CROSS-CHAIN =========
        _configureCrossChain();

        vm.stopBroadcast();

        // ========= 5. LOG RESULTS =========
        _logDeployment();
        _writeDeploymentJson();
    }

    function _validateChainId() internal view {
        require(
            block.chainid == ARBITRUM_SEPOLIA ||
                block.chainid == BASE_SEPOLIA ||
                block.chainid == OPTIMISM_SEPOLIA ||
                block.chainid == SCROLL_SEPOLIA ||
                block.chainid == LINEA_SEPOLIA,
            string.concat(
                "Unsupported testnet chain ID: ",
                vm.toString(block.chainid)
            )
        );
    }

    // ========= CORE CONTRACTS =========

    function _deployCoreContracts(address admin) internal {
        // NullifierRegistryV3 — cross-domain nullifier tracking
        nullifierRegistry = new NullifierRegistryV3();
        console.log("NullifierRegistryV3:", address(nullifierRegistry));

        // BridgeCircuitBreaker — anomaly detection
        circuitBreaker = new BridgeCircuitBreaker(admin);
        console.log("BridgeCircuitBreaker:", address(circuitBreaker));

        // BridgeRateLimiter — rate limiting
        rateLimiter = new BridgeRateLimiter(admin);
        console.log("BridgeRateLimiter:", address(rateLimiter));
    }

    // ========= BRIDGE ADAPTER (per-chain) =========

    function _deployBridgeAdapter(address admin, address deployer) internal {
        if (
            block.chainid == OPTIMISM_SEPOLIA || block.chainid == BASE_SEPOLIA
        ) {
            // OP Stack chains (Optimism Sepolia, Base Sepolia) use OptimismBridgeAdapter
            OptimismBridgeAdapter adapter = new OptimismBridgeAdapter(deployer);
            bridgeAdapter = address(adapter);

            // Grant roles to admin
            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
            adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);
            adapter.grantRole(adapter.RELAYER_ROLE(), admin);

            // Renounce deployer roles (if admin != deployer)
            if (admin != deployer) {
                adapter.renounceRole(adapter.RELAYER_ROLE(), deployer);
                adapter.renounceRole(adapter.TREASURY_ROLE(), deployer);
                adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("OptimismBridgeAdapter:", bridgeAdapter);
        } else if (block.chainid == ARBITRUM_SEPOLIA) {
            ArbitrumBridgeAdapter adapter = new ArbitrumBridgeAdapter(deployer);
            bridgeAdapter = address(adapter);

            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
            adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);
            adapter.grantRole(adapter.EXECUTOR_ROLE(), admin);

            if (admin != deployer) {
                adapter.renounceRole(adapter.EXECUTOR_ROLE(), deployer);
                adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("ArbitrumBridgeAdapter:", bridgeAdapter);
        } else if (block.chainid == SCROLL_SEPOLIA) {
            ScrollBridgeAdapter adapter = new ScrollBridgeAdapter(deployer);
            bridgeAdapter = address(adapter);

            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);

            if (admin != deployer) {
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("ScrollBridgeAdapter:", bridgeAdapter);
        } else if (block.chainid == LINEA_SEPOLIA) {
            LineaBridgeAdapter adapter = new LineaBridgeAdapter(deployer);
            bridgeAdapter = address(adapter);

            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);

            if (admin != deployer) {
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("LineaBridgeAdapter:", bridgeAdapter);
        }
    }

    // ========= PRIVACY CONTRACTS =========

    function _deployPrivacyContracts(address admin) internal {
        stealthRegistry = new StealthAddressRegistry();
        console.log("StealthAddressRegistry:", address(stealthRegistry));

        // Grant admin role
        stealthRegistry.grantRole(stealthRegistry.DEFAULT_ADMIN_ROLE(), admin);
    }

    // ========= CROSS-CHAIN CONFIG =========

    function _configureCrossChain() internal {
        // Register L1 Sepolia as a peer chain
        nullifierRegistry.grantRole(
            nullifierRegistry.REGISTRAR_ROLE(),
            address(this)
        );

        // Register other testnet chain IDs for cross-chain nullifier sync
        uint256[5] memory peerChains = [
            L1_SEPOLIA,
            ARBITRUM_SEPOLIA,
            BASE_SEPOLIA,
            OPTIMISM_SEPOLIA,
            SCROLL_SEPOLIA
        ];

        for (uint256 i; i < peerChains.length; i++) {
            if (peerChains[i] != block.chainid) {
                // Register peer chain for nullifier sync
                nullifierRegistry.registerDomain(bytes32(peerChains[i]));
            }
        }

        console.log("Cross-chain configuration complete");
    }

    // ========= LOGGING =========

    function _logDeployment() internal view {
        string memory network = _networkName();
        console.log("");
        console.log(string.concat("=== ", network, " Deployment Complete ==="));
        console.log("NullifierRegistryV3:", address(nullifierRegistry));
        console.log("BridgeCircuitBreaker:", address(circuitBreaker));
        console.log("BridgeRateLimiter:", address(rateLimiter));
        console.log("StealthAddressRegistry:", address(stealthRegistry));
        console.log("BridgeAdapter:", bridgeAdapter);
        console.log("");
        console.log("Post-deploy steps:");
        console.log("  1. Verify contracts on block explorer");
        console.log(
            "  2. Run ConfigureCrossChain.s.sol to link L1 <-> L2 contracts"
        );
        console.log("  3. Fund relayer addresses with testnet ETH");
        console.log("  4. Run integration tests against live deployment");
        console.log("  5. Update deployments/<network>.json with addresses");
    }

    function _writeDeploymentJson() internal {
        string memory network = _networkName();
        string memory json = string.concat(
            "{\n",
            '  "network": "',
            network,
            '",\n',
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "deployer": "',
            vm.toString(msg.sender),
            '",\n',
            '  "contracts": {\n',
            '    "NullifierRegistryV3": "',
            vm.toString(address(nullifierRegistry)),
            '",\n',
            '    "BridgeCircuitBreaker": "',
            vm.toString(address(circuitBreaker)),
            '",\n',
            '    "BridgeRateLimiter": "',
            vm.toString(address(rateLimiter)),
            '",\n',
            '    "StealthAddressRegistry": "',
            vm.toString(address(stealthRegistry)),
            '",\n',
            '    "BridgeAdapter": "',
            vm.toString(bridgeAdapter),
            '"\n',
            "  }\n",
            "}"
        );
        string memory path = string.concat(
            "deployments/",
            network,
            "-",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeFile(path, json);
        console.log("Deployment JSON written to:", path);
    }

    function _networkName() internal view returns (string memory) {
        if (block.chainid == ARBITRUM_SEPOLIA) return "arbitrum-sepolia";
        if (block.chainid == BASE_SEPOLIA) return "base-sepolia";
        if (block.chainid == OPTIMISM_SEPOLIA) return "optimism-sepolia";
        if (block.chainid == SCROLL_SEPOLIA) return "scroll-sepolia";
        if (block.chainid == LINEA_SEPOLIA) return "linea-sepolia";
        return "unknown";
    }
}
