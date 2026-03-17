// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OptimismBridgeAdapter} from "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import {ArbitrumBridgeAdapter} from "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";
import {AztecBridgeAdapter} from "../../contracts/crosschain/AztecBridgeAdapter.sol";
import {zkSyncBridgeAdapter} from "../../contracts/crosschain/zkSyncBridgeAdapter.sol";
import {ScrollBridgeAdapter} from "../../contracts/crosschain/ScrollBridgeAdapter.sol";
import {LineaBridgeAdapter} from "../../contracts/crosschain/LineaBridgeAdapter.sol";
import {LayerZeroAdapter} from "../../contracts/crosschain/LayerZeroAdapter.sol";
import {HyperlaneAdapter} from "../../contracts/crosschain/HyperlaneAdapter.sol";
import {BitVMAdapter} from "../../contracts/crosschain/BitVMAdapter.sol";

/**
 * @title ZASEON L2 Bridge Deployment Script
 * @notice Deploys bridge adapters to individual L2 networks
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY    - Deployer EOA private key
 *   MULTISIG_ADMIN          - Gnosis Safe on the L2
 *   RELAYER_ADDRESS          - Relayer EOA for the L2
 *   L1_PROOF_HUB            - CrossChainProofHubV3 address on L1
 *
 * For Optimism:
 *   OP_BRIDGE_CONTRACT      - Optimism bridge contract address
 *
 * For Arbitrum:
 *   ARB_INBOX               - Arbitrum Delayed Inbox address
 *   ARB_OUTBOX              - Arbitrum Outbox address
 *   ARB_BRIDGE              - Arbitrum Bridge address
 *   ARB_ROLLUP              - Arbitrum Rollup address
 *
 * For Aztec:
 *   AZTEC_ROLLUP_PROCESSOR  - Aztec rollup processor address
 *   AZTEC_DEFI_BRIDGE       - Aztec DeFi bridge address
 *
 * For zkSync:
 *   ZKSYNC_DIAMOND_PROXY    - zkSync Era Diamond Proxy address
 *   ZKSYNC_L1_BRIDGE        - zkSync L1 shared bridge address
 *
 * For Scroll:
 *   SCROLL_MESSENGER        - Scroll L1/L2 messenger address
 *   SCROLL_GATEWAY_ROUTER   - Scroll L1 gateway router address
 *
 * For Linea:
 *   LINEA_MESSAGE_SERVICE   - Linea message service address
 *   LINEA_TOKEN_BRIDGE      - Linea token bridge address
 *
 * For LayerZero:
 *   LZ_ENDPOINT             - LayerZero V2 endpoint address
 *   LZ_LOCAL_EID            - Local chain's LayerZero endpoint ID
 *
 * For Hyperlane:
 *   HYP_MAILBOX             - Hyperlane Mailbox address
 *   HYP_IGP                 - Interchain Gas Paymaster address
 *   HYP_LOCAL_DOMAIN        - Local Hyperlane domain ID
 *
 * For BitVM:
 *   BITVM_TREASURY          - Treasury address for adapter fee collection
 *
 * Usage:
 *   DEPLOY_TARGET=optimism   forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=arbitrum   forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=aztec      forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=zksync     forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=scroll     forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=linea      forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=layerzero  forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=hyperlane  forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 *   DEPLOY_TARGET=bitvm      forge script scripts/deploy/DeployL2Bridges.s.sol --broadcast
 */
contract DeployL2Bridges is Script {
    function run() external {
        string memory target = vm.envString("DEPLOY_TARGET");
        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);
        address admin = vm.envAddress("MULTISIG_ADMIN");

        require(admin != address(0), "MULTISIG_ADMIN not set");

        console.log("=== Zaseon L2 Bridge Deployment ===");
        console.log("Target:", target);
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", deployer);

        vm.startBroadcast(deployerPK);

        if (_strEq(target, "optimism")) {
            _deployOptimism(admin, deployer);
        } else if (_strEq(target, "arbitrum")) {
            _deployArbitrum(admin, deployer);
        } else if (_strEq(target, "aztec")) {
            _deployAztec(admin, deployer);
        } else if (_strEq(target, "zksync")) {
            _deployZkSync(admin, deployer);
        } else if (_strEq(target, "scroll")) {
            _deployScroll(admin, deployer);
        } else if (_strEq(target, "linea")) {
            _deployLinea(admin, deployer);
        } else if (_strEq(target, "layerzero")) {
            _deployLayerZero(admin, deployer);
        } else if (_strEq(target, "hyperlane")) {
            _deployHyperlane(admin, deployer);
        } else if (_strEq(target, "bitvm")) {
            _deployBitVM(admin, deployer);
        } else {
            revert(string.concat("Unknown deploy target: ", target));
        }

        vm.stopBroadcast();
    }

    function _deployOptimism(address admin, address deployer) internal {
        require(block.chainid == 10, "Expected Optimism chainId 10");

        OptimismBridgeAdapter adapter = new OptimismBridgeAdapter(deployer);
        console.log("OptimismBridgeAdapter:", address(adapter));

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        // Grant relayer role if configured
        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
            console.log("Relayer granted:", relayer);
        }

        // Renounce deployer roles
        adapter.renounceRole(adapter.RELAYER_ROLE(), deployer);
        adapter.renounceRole(adapter.TREASURY_ROLE(), deployer);
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Optimism bridge deployed. Admin:", admin);
        console.log("  Post-deploy: call configure() via multisig");
    }

    function _deployArbitrum(address admin, address deployer) internal {
        require(block.chainid == 42161, "Expected Arbitrum chainId 42161");

        ArbitrumBridgeAdapter adapter = new ArbitrumBridgeAdapter(deployer);
        console.log("ArbitrumBridgeAdapter:", address(adapter));

        // Configure rollup addresses if available
        address inbox = vm.envOr("ARB_INBOX", address(0));
        if (inbox != address(0)) {
            address outbox = vm.envAddress("ARB_OUTBOX");
            address bridge = vm.envAddress("ARB_BRIDGE");
            address rollup = vm.envAddress("ARB_ROLLUP");
            adapter.configureRollup(
                42161,
                inbox,
                outbox,
                bridge,
                rollup,
                ArbitrumBridgeAdapter.RollupType(0)
            );
            console.log("Rollup configured");
        }

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);
        adapter.grantRole(adapter.EXECUTOR_ROLE(), admin);

        // Grant executor role if configured
        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        // Renounce deployer roles
        adapter.renounceRole(adapter.EXECUTOR_ROLE(), deployer);
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Arbitrum bridge deployed. Admin:", admin);
    }

    function _deployAztec(address admin, address deployer) internal {
        address rollupProcessor = vm.envAddress("AZTEC_ROLLUP_PROCESSOR");
        address defiBridge = vm.envAddress("AZTEC_DEFI_BRIDGE");

        AztecBridgeAdapter adapter = new AztecBridgeAdapter(
            rollupProcessor,
            defiBridge,
            deployer
        );
        console.log("AztecBridgeAdapter:", address(adapter));

        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
            console.log("Relayer granted:", relayer);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Aztec bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.AZTEC"
        );
    }

    function _deployZkSync(address admin, address deployer) internal {
        zkSyncBridgeAdapter adapter = new zkSyncBridgeAdapter(deployer);
        console.log("zkSyncBridgeAdapter:", address(adapter));

        // Configure bridge if addresses available
        address diamondProxy = vm.envOr("ZKSYNC_DIAMOND_PROXY", address(0));
        if (diamondProxy != address(0)) {
            address l1Bridge = vm.envAddress("ZKSYNC_L1_BRIDGE");
            address l2Bridge = vm.envAddress("ZKSYNC_L2_BRIDGE");
            adapter.configureBridge(
                324, // zkSync Era chain ID
                diamondProxy,
                l1Bridge,
                l2Bridge
            );
            console.log("Bridge configured");
        }

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        // Renounce deployer roles
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("zkSync bridge deployed. Admin:", admin);
    }

    function _deployScroll(address admin, address deployer) internal {
        ScrollBridgeAdapter adapter = new ScrollBridgeAdapter(deployer);
        console.log("ScrollBridgeAdapter:", address(adapter));

        // Configure Scroll if addresses available
        address messenger = vm.envOr("SCROLL_MESSENGER", address(0));
        if (messenger != address(0)) {
            address gatewayRouter = vm.envAddress("SCROLL_GATEWAY_ROUTER");
            address messageQueue = vm.envAddress("SCROLL_MESSAGE_QUEUE");
            address rollup = vm.envAddress("SCROLL_ROLLUP");
            adapter.configureScroll(
                534352, // Scroll chain ID
                messenger,
                gatewayRouter,
                messageQueue,
                rollup
            );
            console.log("Scroll bridge configured");
        }

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Scroll bridge deployed. Admin:", admin);
    }

    function _deployLinea(address admin, address deployer) internal {
        LineaBridgeAdapter adapter = new LineaBridgeAdapter(deployer);
        console.log("LineaBridgeAdapter:", address(adapter));

        // Configure Linea if addresses available
        address messageService = vm.envOr("LINEA_MESSAGE_SERVICE", address(0));
        if (messageService != address(0)) {
            address tokenBridge = vm.envAddress("LINEA_TOKEN_BRIDGE");
            adapter.configureLinea(
                59144, // Linea chain ID
                messageService,
                tokenBridge
            );
            console.log("Linea bridge configured");
        }

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Linea bridge deployed. Admin:", admin);
    }

    function _deployLayerZero(address admin, address deployer) internal {
        address lzEndpoint = vm.envAddress("LZ_ENDPOINT");
        uint32 localEid = uint32(vm.envUint("LZ_LOCAL_EID"));

        LayerZeroAdapter adapter = new LayerZeroAdapter(
            deployer,
            lzEndpoint,
            localEid
        );
        console.log("LayerZeroAdapter:", address(adapter));

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("LayerZero bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: call configureEndpoint() and setPeer() via multisig"
        );
    }

    function _deployHyperlane(address admin, address deployer) internal {
        address hypMailbox = vm.envAddress("HYP_MAILBOX");
        address hypIgp = vm.envOr("HYP_IGP", address(0));
        uint32 localDomain = uint32(vm.envUint("HYP_LOCAL_DOMAIN"));

        HyperlaneAdapter adapter = new HyperlaneAdapter(
            deployer,
            hypMailbox,
            hypIgp,
            localDomain
        );
        console.log("HyperlaneAdapter:", address(adapter));

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
            console.log("Relayer granted:", relayer);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Hyperlane bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: call configureDomain() and configureISM() via multisig"
        );
    }

    function _deployBitVM(address admin, address deployer) internal {
        address treasury = vm.envAddress("BITVM_TREASURY");

        BitVMAdapter adapter = new BitVMAdapter(deployer, treasury);
        console.log("BitVMAdapter:", address(adapter));

        // Transfer roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), admin);

        address guardian = vm.envOr("RELAYER_ADDRESS", address(0));
        if (guardian != address(0)) {
            adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
            console.log("Guardian granted:", guardian);
        }

        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("BitVM bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: setChallengeWindow()/setFeeParams() via multisig"
        );
    }

    function _strEq(
        string memory a,
        string memory b
    ) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
