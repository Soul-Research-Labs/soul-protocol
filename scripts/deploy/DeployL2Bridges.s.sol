// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {OptimismBridgeAdapter} from "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import {ArbitrumBridgeAdapter} from "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";
import {BaseBridgeAdapter} from "../../contracts/crosschain/BaseBridgeAdapter.sol";

/**
 * @title Soul Protocol L2 Bridge Deployment Script
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
 */
contract DeployL2Bridges is Script {
    function run() external {
        string memory target = vm.envString("DEPLOY_TARGET");
        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);
        address admin = vm.envAddress("MULTISIG_ADMIN");

        require(admin != address(0), "MULTISIG_ADMIN not set");

        console.log("=== Soul L2 Bridge Deployment ===");
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

    function _strEq(
        string memory a,
        string memory b
    ) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
