// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

// Core contracts
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {ConfidentialStateContainerV3} from "../../contracts/core/ConfidentialStateContainerV3.sol";

// Bridge adapters
import {OptimismRelayAdapter} from "../../contracts/crosschain/OptimismRelayAdapter.sol";
import {ArbitrumRelayAdapter} from "../../contracts/crosschain/ArbitrumRelayAdapter.sol";
import {BaseRelayAdapter} from "../../contracts/crosschain/BaseRelayAdapter.sol";
import {ScrollRelayAdapter} from "../../contracts/crosschain/ScrollRelayAdapter.sol";
import {LineaRelayAdapter} from "../../contracts/crosschain/LineaRelayAdapter.sol";

// Security
import {RelayCircuitBreaker} from "../../contracts/security/RelayCircuitBreaker.sol";
import {RelayRateLimiter} from "../../contracts/security/RelayRateLimiter.sol";

// Privacy
import {StealthAddressRegistry} from "../../contracts/privacy/StealthAddressRegistry.sol";

// Proxy for upgradeable contracts
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ZASEON L2 Testnet Deployment Script
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
    RelayCircuitBreaker public circuitBreaker;
    RelayRateLimiter public rateLimiter;
    StealthAddressRegistry public stealthRegistry;
    address public relayAdapter;

    function run() external {
        // Accept private key with or without 0x prefix
        uint256 deployerPK = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (deployerPK == 0) {
            // Try reading as string and parsing with 0x prefix
            string memory pkStr = vm.envString("DEPLOYER_PRIVATE_KEY");
            deployerPK = vm.parseUint(string.concat("0x", pkStr));
        }
        require(deployerPK != 0, "DEPLOYER_PRIVATE_KEY not set or invalid");
        address deployer = vm.addr(deployerPK);
        // On testnets, admin can be the deployer for simplicity
        address admin = vm.envOr("TESTNET_ADMIN", deployer);

        console.log("=== ZASEON L2 Testnet Deployment ===");
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", deployer);
        console.log("Admin:", admin);

        _validateChainId();

        vm.startBroadcast(deployerPK);

        // ========= 1. DEPLOY CORE CONTRACTS =========
        _deployCoreContracts(admin);

        // ========= 2. DEPLOY CHAIN-SPECIFIC BRIDGE =========
        _deployRelayAdapter(admin, deployer);

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

        // RelayCircuitBreaker — anomaly detection
        circuitBreaker = new RelayCircuitBreaker(admin);
        console.log("RelayCircuitBreaker:", address(circuitBreaker));

        // RelayRateLimiter — rate limiting
        rateLimiter = new RelayRateLimiter(admin);
        console.log("RelayRateLimiter:", address(rateLimiter));
    }

    // ========= BRIDGE ADAPTER (per-chain) =========

    function _deployRelayAdapter(address admin, address deployer) internal {
        if (
            block.chainid == OPTIMISM_SEPOLIA || block.chainid == BASE_SEPOLIA
        ) {
            // OP Stack chains (Optimism Sepolia, Base Sepolia) use OptimismRelayAdapter
            OptimismRelayAdapter adapter = new OptimismRelayAdapter(deployer);
            relayAdapter = address(adapter);

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

            console.log("OptimismRelayAdapter:", relayAdapter);
        } else if (block.chainid == ARBITRUM_SEPOLIA) {
            ArbitrumRelayAdapter adapter = new ArbitrumRelayAdapter(deployer);
            relayAdapter = address(adapter);

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

            console.log("ArbitrumRelayAdapter:", relayAdapter);
        } else if (block.chainid == SCROLL_SEPOLIA) {
            // Scroll requires messenger, gateway, rollup, and admin addresses
            address scrollMessenger = vm.envOr("SCROLL_MESSENGER", address(0));
            address scrollGateway = vm.envOr(
                "SCROLL_GATEWAY_ROUTER",
                address(0)
            );
            address scrollRollup = vm.envOr(
                "SCROLL_ROLLUP_CONTRACT",
                address(0)
            );
            ScrollRelayAdapter adapter = new ScrollRelayAdapter(
                scrollMessenger,
                scrollGateway,
                scrollRollup,
                admin
            );
            relayAdapter = address(adapter);

            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);

            if (admin != deployer) {
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("ScrollRelayAdapter:", relayAdapter);
        } else if (block.chainid == LINEA_SEPOLIA) {
            // Linea requires message service, token bridge, rollup, and admin addresses
            address lineaMessageService = vm.envOr(
                "LINEA_MESSAGE_SERVICE",
                address(0)
            );
            address lineaTokenBridge = vm.envOr(
                "LINEA_TOKEN_BRIDGE",
                address(0)
            );
            address lineaRollup = vm.envOr("LINEA_ROLLUP", address(0));
            LineaRelayAdapter adapter = new LineaRelayAdapter(
                lineaMessageService,
                lineaTokenBridge,
                lineaRollup,
                admin
            );
            relayAdapter = address(adapter);

            adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
            adapter.grantRole(adapter.OPERATOR_ROLE(), admin);

            if (admin != deployer) {
                adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
                adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
            }

            console.log("LineaRelayAdapter:", relayAdapter);
        }
    }

    // ========= PRIVACY CONTRACTS =========

    function _deployPrivacyContracts(address admin) internal {
        // StealthAddressRegistry is upgradeable — deploy implementation + initialize
        // For testnet, we deploy without a proxy and call initialize directly
        StealthAddressRegistry impl = new StealthAddressRegistry();

        // Deploy behind an ERC1967 proxy so initialize() can be called
        bytes memory initData = abi.encodeCall(
            StealthAddressRegistry.initialize,
            (admin)
        );
        address proxy = address(new ERC1967Proxy(address(impl), initData));
        stealthRegistry = StealthAddressRegistry(proxy);

        console.log(
            "StealthAddressRegistry (proxy):",
            address(stealthRegistry)
        );
        console.log("StealthAddressRegistry (impl):", address(impl));
    }

    // ========= CROSS-CHAIN CONFIG =========

    function _configureCrossChain() internal {
        // NullifierRegistryV3 constructor already grants REGISTRAR_ROLE to deployer (msg.sender)
        // so we can register domains directly without additional role grants.

        // Register other testnet chain IDs for cross-chain nullifier sync
        uint256[6] memory peerChains = [
            L1_SEPOLIA,
            ARBITRUM_SEPOLIA,
            BASE_SEPOLIA,
            OPTIMISM_SEPOLIA,
            SCROLL_SEPOLIA,
            LINEA_SEPOLIA
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
        console.log("RelayCircuitBreaker:", address(circuitBreaker));
        console.log("RelayRateLimiter:", address(rateLimiter));
        console.log("StealthAddressRegistry:", address(stealthRegistry));
        console.log("RelayAdapter:", relayAdapter);
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
            '    "RelayCircuitBreaker": "',
            vm.toString(address(circuitBreaker)),
            '",\n',
            '    "RelayRateLimiter": "',
            vm.toString(address(rateLimiter)),
            '",\n',
            '    "StealthAddressRegistry": "',
            vm.toString(address(stealthRegistry)),
            '",\n',
            '    "RelayAdapter": "',
            vm.toString(relayAdapter),
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
