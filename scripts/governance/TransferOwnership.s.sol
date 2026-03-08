// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../contracts/governance/ZaseonUpgradeTimelock.sol";
import "../../contracts/crosschain/ZaseonCrossChainRelay.sol";
import "../../contracts/crosschain/MessageBatcher.sol";

/// @notice Transfer protocol admin roles to a ZaseonUpgradeTimelock instance.
/// @dev Replaces the deprecated ZaseonGovernance-based flow. The timelock
///      is used by ZaseonGovernor for queuing and executing proposals.
contract TransferOwnership is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Addresses (must be set via env)
        address timelockAddr = vm.envAddress("TIMELOCK_ADDRESS");
        address relayAddr = vm.envAddress("RELAY_ADDRESS");
        address batcherAddr = vm.envAddress("BATCHER_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        ZaseonUpgradeTimelock timelock = ZaseonUpgradeTimelock(
            payable(timelockAddr)
        );
        console.log("Using ZaseonUpgradeTimelock:", address(timelock));

        // 1. Transfer Relay Admin
        ZaseonCrossChainRelay relay = ZaseonCrossChainRelay(relayAddr);
        relay.grantRole(relay.DEFAULT_ADMIN_ROLE(), address(timelock));
        relay.revokeRole(relay.DEFAULT_ADMIN_ROLE(), deployer);
        console.log("Transferred Relay Admin to Timelock");

        // 2. Transfer Batcher Admin if applicable
        if (batcherAddr != address(0)) {
            MessageBatcher batcher = MessageBatcher(batcherAddr);
            batcher.grantRole(batcher.DEFAULT_ADMIN_ROLE(), address(timelock));
            batcher.revokeRole(batcher.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Batcher Admin to Timelock");
        }

        vm.stopBroadcast();
    }
}
