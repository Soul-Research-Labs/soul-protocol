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
import {SolanaBridgeAdapter} from "../../contracts/crosschain/SolanaBridgeAdapter.sol";
import {CardanoBridgeAdapter} from "../../contracts/crosschain/CardanoBridgeAdapter.sol";
import {MidnightBridgeAdapter} from "../../contracts/crosschain/MidnightBridgeAdapter.sol";
import {RailgunBridgeAdapter} from "../../contracts/crosschain/RailgunBridgeAdapter.sol";
import {AztecBridgeAdapter} from "../../contracts/crosschain/AztecBridgeAdapter.sol";
import {SecretBridgeAdapter} from "../../contracts/crosschain/SecretBridgeAdapter.sol";
import {PolkadotBridgeAdapter} from "../../contracts/crosschain/PolkadotBridgeAdapter.sol";
import {CosmosBridgeAdapter} from "../../contracts/crosschain/CosmosBridgeAdapter.sol";
import {ZcashBridgeAdapter} from "../../contracts/crosschain/ZcashBridgeAdapter.sol";
import {PenumbraBridgeAdapter} from "../../contracts/crosschain/PenumbraBridgeAdapter.sol";
import {NEARBridgeAdapter} from "../../contracts/crosschain/NEARBridgeAdapter.sol";
import {AvalancheBridgeAdapter} from "../../contracts/crosschain/AvalancheBridgeAdapter.sol";
import {AxelarBridgeAdapter} from "../../contracts/crosschain/AxelarBridgeAdapter.sol";

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
 *
 *   # Solana (Wormhole bridge on EVM)
 *   DEPLOY_TARGET=solana forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ETH_RPC --broadcast --verify -vvv
 *
 *   # Cardano (Wormhole bridge on EVM)
 *   DEPLOY_TARGET=cardano forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ETH_RPC --broadcast --verify -vvv
 *
 *   # Midnight (native bridge on EVM)
 *   DEPLOY_TARGET=midnight forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ETH_RPC --broadcast --verify -vvv
 *
 *   # Railgun (EVM-native privacy protocol)
 *   DEPLOY_TARGET=railgun forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ETH_RPC --broadcast --verify -vvv
 *
 *   # Aztec (privacy ZK-rollup on Ethereum)
 *   DEPLOY_TARGET=aztec forge script scripts/deploy/DeployL2Bridges.s.sol \
 *     --rpc-url $ETH_RPC --broadcast --verify -vvv
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
        } else if (_strEq(target, "solana")) {
            _deploySolana(admin, deployer);
        } else if (_strEq(target, "cardano")) {
            _deployCardano(admin, deployer);
        } else if (_strEq(target, "midnight")) {
            _deployMidnight(admin, deployer);
        } else if (_strEq(target, "railgun")) {
            _deployRailgun(admin, deployer);
        } else if (_strEq(target, "aztec")) {
            _deployAztec(admin, deployer);
        } else if (_strEq(target, "secret")) {
            _deploySecret(admin, deployer);
        } else if (_strEq(target, "polkadot")) {
            _deployPolkadot(admin, deployer);
        } else if (_strEq(target, "cosmos")) {
            _deployCosmos(admin, deployer);
        } else if (_strEq(target, "zcash")) {
            _deployZcash(admin, deployer);
        } else if (_strEq(target, "penumbra")) {
            _deployPenumbra(admin, deployer);
        } else if (_strEq(target, "near")) {
            _deployNEAR(admin, deployer);
        } else if (_strEq(target, "avalanche")) {
            _deployAvalanche(admin, deployer);
        } else if (_strEq(target, "axelar")) {
            _deployAxelar(admin, deployer);
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

    function _deploySolana(address admin, address deployer) internal {
        address wormholeCore = vm.envAddress("WORMHOLE_CORE");
        address wormholeTokenBridge = vm.envAddress("WORMHOLE_TOKEN_BRIDGE");

        SolanaBridgeAdapter adapter = new SolanaBridgeAdapter(
            wormholeCore,
            wormholeTokenBridge,
            deployer
        );
        console.log("SolanaBridgeAdapter:", address(adapter));

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

        console.log("Solana bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: setZaseonSolanaProgram() + setWhitelistedProgram() via multisig"
        );
    }

    function _deployCardano(address admin, address deployer) internal {
        address wormholeCore = vm.envAddress("WORMHOLE_CORE");
        address wormholeTokenBridge = vm.envAddress("WORMHOLE_TOKEN_BRIDGE");

        CardanoBridgeAdapter adapter = new CardanoBridgeAdapter(
            wormholeCore,
            wormholeTokenBridge,
            deployer
        );
        console.log("CardanoBridgeAdapter:", address(adapter));

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

        console.log("Cardano bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: setZaseonCardanoValidator() + setWhitelistedValidator() via multisig"
        );
    }

    function _deployMidnight(address admin, address deployer) internal {
        address midnightBridge = vm.envAddress("MIDNIGHT_BRIDGE");
        address proofVerifier = vm.envAddress("MIDNIGHT_PROOF_VERIFIER");

        MidnightBridgeAdapter adapter = new MidnightBridgeAdapter(
            midnightBridge,
            proofVerifier,
            deployer
        );
        console.log("MidnightBridgeAdapter:", address(adapter));

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

        console.log("Midnight bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: setZaseonMidnightContract() + setWhitelistedContract() via multisig"
        );
    }

    function _deployRailgun(address admin, address deployer) internal {
        address railgunWallet = vm.envAddress("RAILGUN_SMART_WALLET");
        address railgunRelay = vm.envAddress("RAILGUN_RELAY_ADAPT");

        RailgunBridgeAdapter adapter = new RailgunBridgeAdapter(
            railgunWallet,
            railgunRelay,
            deployer
        );
        console.log("RailgunBridgeAdapter:", address(adapter));

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

        console.log("Railgun bridge deployed. Admin:", admin);
        console.log("  Post-deploy: grantRole(RELAYER_ROLE) via multisig");
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

    function _deploySecret(address admin, address deployer) internal {
        address secretGateway = vm.envAddress("SECRET_GATEWAY");
        address secretVerifier = vm.envAddress("SECRET_VERIFIER");

        SecretBridgeAdapter adapter = new SecretBridgeAdapter(
            secretGateway,
            secretVerifier,
            deployer
        );
        console.log("SecretBridgeAdapter:", address(adapter));

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

        console.log("Secret bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.SECRET"
        );
    }

    function _deployPolkadot(address admin, address deployer) internal {
        address snowbridgeGateway = vm.envAddress("SNOWBRIDGE_GATEWAY");
        address beefyVerifier = vm.envAddress("BEEFY_VERIFIER");

        PolkadotBridgeAdapter adapter = new PolkadotBridgeAdapter(
            snowbridgeGateway,
            beefyVerifier,
            deployer
        );
        console.log("PolkadotBridgeAdapter:", address(adapter));

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

        console.log("Polkadot bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.POLKADOT"
        );
    }

    function _deployCosmos(address admin, address deployer) internal {
        address gravityBridge = vm.envAddress("GRAVITY_BRIDGE");
        address ibcLightClient = vm.envAddress("IBC_LIGHT_CLIENT");

        CosmosBridgeAdapter adapter = new CosmosBridgeAdapter(
            gravityBridge,
            ibcLightClient,
            deployer
        );
        console.log("CosmosBridgeAdapter:", address(adapter));

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

        console.log("Cosmos bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.COSMOS"
        );
    }

    function _deployZcash(address admin, address deployer) internal {
        address zcashBridge = vm.envAddress("ZCASH_BRIDGE");
        address orchardVerifier = vm.envAddress("ORCHARD_VERIFIER");

        ZcashBridgeAdapter adapter = new ZcashBridgeAdapter(
            zcashBridge,
            orchardVerifier,
            deployer
        );
        console.log("ZcashBridgeAdapter:", address(adapter));

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

        console.log("Zcash bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.ZCASH"
        );
    }

    function _deployPenumbra(address admin, address deployer) internal {
        address penumbraBridge = vm.envAddress("PENUMBRA_BRIDGE");
        address penumbraVerifier = vm.envAddress("PENUMBRA_VERIFIER");

        PenumbraBridgeAdapter adapter = new PenumbraBridgeAdapter(
            penumbraBridge,
            penumbraVerifier,
            deployer
        );
        console.log("PenumbraBridgeAdapter:", address(adapter));

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

        console.log("Penumbra bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.PENUMBRA"
        );
    }

    function _deployNEAR(address admin, address deployer) internal {
        address nearBridge = vm.envAddress("NEAR_BRIDGE");
        address nearLightClient = vm.envAddress("NEAR_LIGHT_CLIENT");

        NEARBridgeAdapter adapter = new NEARBridgeAdapter(
            nearBridge,
            nearLightClient,
            deployer
        );
        console.log("NEARBridgeAdapter:", address(adapter));

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

        console.log("NEAR bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.NEAR"
        );
    }

    function _deployAvalanche(address admin, address deployer) internal {
        address avalancheBridge = vm.envAddress("AVALANCHE_BRIDGE");
        address warpVerifier = vm.envAddress("WARP_VERIFIER");

        AvalancheBridgeAdapter adapter = new AvalancheBridgeAdapter(
            avalancheBridge,
            warpVerifier,
            deployer
        );
        console.log("AvalancheBridgeAdapter:", address(adapter));

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

        console.log("Avalanche bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register in MultiBridgeRouter with BridgeType.AVALANCHE"
        );
    }

    function _deployAxelar(address admin, address deployer) internal {
        address axelarGateway = vm.envAddress("AXELAR_GATEWAY");
        address axelarGasService = vm.envAddress("AXELAR_GAS_SERVICE");

        AxelarBridgeAdapter adapter = new AxelarBridgeAdapter(
            axelarGateway,
            axelarGasService,
            deployer
        );
        console.log("AxelarBridgeAdapter:", address(adapter));

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

        console.log("Axelar bridge deployed. Admin:", admin);
        console.log(
            "  Post-deploy: register chains via registerChain(), then register in MultiBridgeRouter with BridgeType.AXELAR"
        );
    }

    function _strEq(
        string memory a,
        string memory b
    ) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
