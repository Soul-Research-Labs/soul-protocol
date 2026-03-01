// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OptimismBridgeAdapter} from "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import {ArbitrumBridgeAdapter} from "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";
import {BaseBridgeAdapter} from "../../contracts/crosschain/BaseBridgeAdapter.sol";
import {ScrollBridgeAdapter} from "../../contracts/crosschain/ScrollBridgeAdapter.sol";
import {LineaBridgeAdapter} from "../../contracts/crosschain/LineaBridgeAdapter.sol";
import {zkSyncBridgeAdapter} from "../../contracts/crosschain/zkSyncBridgeAdapter.sol";
import {PolygonZkEVMBridgeAdapter} from "../../contracts/crosschain/PolygonZkEVMBridgeAdapter.sol";
import {StarknetBridgeAdapter} from "../../contracts/crosschain/StarknetBridgeAdapter.sol";
import {MantleBridgeAdapter} from "../../contracts/crosschain/MantleBridgeAdapter.sol";
import {BlastBridgeAdapter} from "../../contracts/crosschain/BlastBridgeAdapter.sol";
import {TaikoBridgeAdapter} from "../../contracts/crosschain/TaikoBridgeAdapter.sol";
import {ModeBridgeAdapter} from "../../contracts/crosschain/ModeBridgeAdapter.sol";
import {MantaPacificBridgeAdapter} from "../../contracts/crosschain/MantaPacificBridgeAdapter.sol";

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
 *   OP_L1_OUTPUT_ORACLE     - L1OutputOracle address
 *
 * For Arbitrum:
 *   ARB_INBOX               - Arbitrum Inbox
 *   ARB_OUTBOX              - Arbitrum Outbox
 *   ARB_BRIDGE              - Arbitrum Bridge
 *   ARB_ROLLUP              - Arbitrum Rollup
 *
 * For Scroll:
 *   SCROLL_MESSENGER        - L1/L2 Scroll Messenger
 *   SCROLL_GATEWAY_ROUTER   - Scroll Gateway Router
 *   SCROLL_ROLLUP           - Scroll Rollup contract
 *
 * For Linea:
 *   LINEA_MESSAGE_SERVICE   - Linea Message Service
 *   LINEA_TOKEN_BRIDGE      - Linea Token Bridge
 *   LINEA_ROLLUP            - Linea Rollup contract
 *
 * Usage:
 *   # Optimism
 *   DEPLOY_TARGET=optimism forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $OPTIMISM_RPC --broadcast --verify -vvv
 *
 *   # Arbitrum
 *   DEPLOY_TARGET=arbitrum forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ARBITRUM_RPC --broadcast --verify -vvv
 *   # Base
 *   DEPLOY_TARGET=base forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $BASE_RPC --broadcast --verify -vvv
 *
 *   # Scroll
 *   DEPLOY_TARGET=scroll forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $SCROLL_RPC --broadcast --verify -vvv
 *
 *   # Linea
 *   DEPLOY_TARGET=linea forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $LINEA_RPC --broadcast --verify -vvv
 *
 *   # zkSync Era
 *   DEPLOY_TARGET=zksync forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ZKSYNC_RPC --broadcast --verify -vvv
 *
 *   # Polygon zkEVM
 *   DEPLOY_TARGET=polygon-zkevm forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $POLYGON_ZKEVM_RPC --broadcast --verify -vvv
 *
 *   # Starknet (requires Starknet RPC)
 *   DEPLOY_TARGET=starknet forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $STARKNET_RPC --broadcast --verify -vvv
 *
 *   # Mantle
 *   DEPLOY_TARGET=mantle forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $MANTLE_RPC --broadcast --verify -vvv
 *
 *   # Blast
 *   DEPLOY_TARGET=blast forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $BLAST_RPC --broadcast --verify -vvv
 *
 *   # Taiko
 *   DEPLOY_TARGET=taiko forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $TAIKO_RPC --broadcast --verify -vvv
 *
 *   # Mode
 *   DEPLOY_TARGET=mode forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $MODE_RPC --broadcast --verify -vvv
 *
 *   # Manta Pacific
 *   DEPLOY_TARGET=manta forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $MANTA_RPC --broadcast --verify -vvv
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
        } else if (_strEq(target, "base")) {
            _deployBase(admin, deployer);
        } else if (_strEq(target, "scroll")) {
            _deployScroll(admin, deployer);
        } else if (_strEq(target, "linea")) {
            _deployLinea(admin, deployer);
        } else if (_strEq(target, "zksync")) {
            _deployZkSync(admin, deployer);
        } else if (_strEq(target, "polygon-zkevm")) {
            _deployPolygonZkEVM(admin, deployer);
        } else if (_strEq(target, "starknet")) {
            _deployStarknet(admin, deployer);
        } else if (_strEq(target, "mantle")) {
            _deployMantle(admin, deployer);
        } else if (_strEq(target, "blast")) {
            _deployBlast(admin, deployer);
        } else if (_strEq(target, "taiko")) {
            _deployTaiko(admin, deployer);
        } else if (_strEq(target, "mode")) {
            _deployMode(admin, deployer);
        } else if (_strEq(target, "manta")) {
            _deployManta(admin, deployer);
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

        // Grant executor role if configured
        address relayer = vm.envOr("RELAYER_ADDRESS", address(0));
        if (relayer != address(0)) {
            adapter.grantRole(adapter.EXECUTOR_ROLE(), relayer);
            console.log("Executor granted:", relayer);
        }

        // Renounce deployer roles
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Arbitrum bridge deployed. Admin:", admin);
    }

    function _deployBase(address admin, address deployer) internal {
        require(block.chainid == 8453, "Expected Base chainId 8453");

        // Base uses OP Stack: L1CrossDomainMessenger + L2CrossDomainMessenger + BasePortal
        address l1Messenger = vm.envOr("BASE_L1_MESSENGER", address(0));
        address l2Messenger = vm.envOr("BASE_L2_MESSENGER", address(0));
        address basePortal = vm.envOr("BASE_PORTAL", address(0));

        BaseBridgeAdapter adapter = new BaseBridgeAdapter(
            deployer,
            l1Messenger,
            l2Messenger,
            basePortal,
            false // isL1 = false (deploying on Base L2)
        );
        console.log("BaseBridgeAdapter:", address(adapter));

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
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Base bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: configure CCTP and attestation via multisig"
        );
    }

    function _deployScroll(address admin, address deployer) internal {
        require(block.chainid == 534352, "Expected Scroll chainId 534352");

        address scrollMessenger = vm.envAddress("SCROLL_MESSENGER");
        address gatewayRouter = vm.envAddress("SCROLL_GATEWAY_ROUTER");
        address rollupContract = vm.envAddress("SCROLL_ROLLUP");

        ScrollBridgeAdapter adapter = new ScrollBridgeAdapter(
            scrollMessenger,
            gatewayRouter,
            rollupContract,
            deployer
        );
        console.log("ScrollBridgeAdapter:", address(adapter));

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
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Scroll bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: configure zaseonHubL2 and proof registry via multisig"
        );
    }

    function _deployLinea(address admin, address deployer) internal {
        require(block.chainid == 59144, "Expected Linea chainId 59144");

        address messageService = vm.envAddress("LINEA_MESSAGE_SERVICE");
        address tokenBridge = vm.envAddress("LINEA_TOKEN_BRIDGE");
        address rollup = vm.envAddress("LINEA_ROLLUP");

        LineaBridgeAdapter adapter = new LineaBridgeAdapter(
            messageService,
            tokenBridge,
            rollup,
            deployer
        );
        console.log("LineaBridgeAdapter:", address(adapter));

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
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Linea bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: configure proof relay and anchoring via multisig"
        );
    }

    function _deployZkSync(address admin, address deployer) internal {
        require(block.chainid == 324, "Expected zkSync Era chainId 324");

        address zkSyncDiamond = vm.envAddress("ZKSYNC_DIAMOND");

        zkSyncBridgeAdapter adapter = new zkSyncBridgeAdapter(
            deployer,
            zkSyncDiamond
        );
        console.log("zkSyncBridgeAdapter:", address(adapter));

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
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("zkSync Era bridge deployed. Admin:", admin);
        console.log("  Post-deploy: call configureZkSyncBridge() via multisig");
    }

    function _deployPolygonZkEVM(address admin, address deployer) internal {
        require(block.chainid == 1101, "Expected Polygon zkEVM chainId 1101");

        address polygonBridge = vm.envAddress("POLYGON_ZKEVM_BRIDGE");
        address exitRootManager = vm.envAddress(
            "POLYGON_ZKEVM_EXIT_ROOT_MANAGER"
        );
        address polygonZkEVM = vm.envAddress("POLYGON_ZKEVM_CONTRACT");
        uint32 networkId = uint32(
            vm.envOr("POLYGON_ZKEVM_NETWORK_ID", uint256(1))
        );

        PolygonZkEVMBridgeAdapter adapter = new PolygonZkEVMBridgeAdapter(
            polygonBridge,
            exitRootManager,
            polygonZkEVM,
            networkId,
            deployer
        );
        console.log("PolygonZkEVMBridgeAdapter:", address(adapter));

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
        adapter.renounceRole(adapter.GUARDIAN_ROLE(), deployer);
        adapter.renounceRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.renounceRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);

        console.log("Polygon zkEVM bridge deployed. Admin:", admin);
        console.log("  Post-deploy: configure zaseonHubL2 via multisig");
    }

    function _deployStarknet(address admin, address deployer) internal {
        address starknetCore = vm.envAddress("STARKNET_CORE");

        StarknetBridgeAdapter adapter = new StarknetBridgeAdapter(
            starknetCore,
            deployer
        );
        console.log("StarknetBridgeAdapter:", address(adapter));

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

        console.log("Starknet bridge deployed. Admin:", admin);
        console.log("  Post-deploy: configure zaseonHubStarknet via multisig");
    }

    function _deployMantle(address admin, address deployer) internal {
        require(block.chainid == 5000, "Expected Mantle chainId 5000");

        address crossDomainMessenger = vm.envAddress(
            "MANTLE_CROSS_DOMAIN_MESSENGER"
        );
        address outputOracle = vm.envAddress("MANTLE_OUTPUT_ORACLE");
        address mantlePortal = vm.envAddress("MANTLE_PORTAL");

        MantleBridgeAdapter adapter = new MantleBridgeAdapter(
            crossDomainMessenger,
            outputOracle,
            mantlePortal,
            deployer
        );
        console.log("MantleBridgeAdapter:", address(adapter));

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

        console.log("Mantle bridge deployed. Admin:", admin);
        console.log("  Post-deploy: configure zaseonHubL2 via multisig");
    }

    function _deployBlast(address admin, address deployer) internal {
        require(block.chainid == 81457, "Expected Blast chainId 81457");

        address crossDomainMessenger = vm.envAddress(
            "BLAST_CROSS_DOMAIN_MESSENGER"
        );
        address blastPortal = vm.envAddress("BLAST_PORTAL");
        address outputOracle = vm.envAddress("BLAST_OUTPUT_ORACLE");

        BlastBridgeAdapter adapter = new BlastBridgeAdapter(
            crossDomainMessenger,
            blastPortal,
            outputOracle,
            deployer
        );
        console.log("BlastBridgeAdapter:", address(adapter));

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

        console.log("Blast bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: configure yield settings and zaseonHubL2 via multisig"
        );
    }

    function _deployTaiko(address admin, address deployer) internal {
        require(block.chainid == 167000, "Expected Taiko chainId 167000");

        address signalService = vm.envAddress("TAIKO_SIGNAL_SERVICE");
        address taikoBridge = vm.envAddress("TAIKO_BRIDGE");
        address taikoL1 = vm.envAddress("TAIKO_L1");

        TaikoBridgeAdapter adapter = new TaikoBridgeAdapter(
            signalService,
            taikoBridge,
            taikoL1,
            deployer
        );
        console.log("TaikoBridgeAdapter:", address(adapter));

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

        console.log("Taiko bridge deployed. Admin:", admin);
        console.log("  Post-deploy: configure zaseonHubL2 via multisig");
    }

    function _deployMode(address admin, address deployer) internal {
        require(block.chainid == 34443, "Expected Mode chainId 34443");

        address crossDomainMessenger = vm.envAddress(
            "MODE_CROSS_DOMAIN_MESSENGER"
        );
        address modePortal = vm.envAddress("MODE_PORTAL");
        address outputOracle = vm.envAddress("MODE_OUTPUT_ORACLE");

        ModeBridgeAdapter adapter = new ModeBridgeAdapter(
            crossDomainMessenger,
            modePortal,
            outputOracle,
            deployer
        );
        console.log("ModeBridgeAdapter:", address(adapter));

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

        console.log("Mode bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: configure SFS registration and zaseonHubL2 via multisig"
        );
    }

    function _deployManta(address admin, address deployer) internal {
        require(block.chainid == 169, "Expected Manta Pacific chainId 169");

        address cdkBridge = vm.envAddress("MANTA_CDK_BRIDGE");
        address exitRootManager = vm.envAddress("MANTA_EXIT_ROOT_MANAGER");
        address mantaRollup = vm.envAddress("MANTA_ROLLUP");
        uint32 networkId = uint32(vm.envOr("MANTA_NETWORK_ID", uint256(1)));

        MantaPacificBridgeAdapter adapter = new MantaPacificBridgeAdapter(
            cdkBridge,
            exitRootManager,
            mantaRollup,
            networkId,
            deployer
        );
        console.log("MantaPacificBridgeAdapter:", address(adapter));

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

        console.log("Manta Pacific bridge deployed. Admin:", admin);
        console.log("  Post-deploy: configure zaseonHubL2 via multisig");
    }

    function _strEq(
        string memory a,
        string memory b
    ) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
