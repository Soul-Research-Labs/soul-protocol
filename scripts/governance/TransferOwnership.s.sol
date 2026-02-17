// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../contracts/governance/SoulGovernance.sol";
import "../../contracts/crosschain/SoulCrossChainRelay.sol";
import "../../contracts/crosschain/MessageBatcher.sol";

contract TransferOwnership is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        // Addresses (mock or from deployment)
        address relayAddr = vm.envAddress("RELAY_ADDRESS"); // Must be set
        address batcherAddr = vm.envAddress("BATCHER_ADDRESS"); // Must be set (optional if relay only)

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Governance
        address[] memory proposers = new address[](1);
        proposers[0] = deployer; // Deployer can propose initially
        address[] memory executors = new address[](1);
        executors[0] = address(0); // Anyone can execute
        
        SoulGovernance governance = new SoulGovernance(
            2 days,   // 2 day delay
            proposers,
            executors,
            deployer  // Admin
        );

        console.log("Deployed SoulGovernance:", address(governance));

        // 2. Transfer Relay Admin
        SoulCrossChainRelay relay = SoulCrossChainRelay(relayAddr);
        relay.grantRole(relay.DEFAULT_ADMIN_ROLE(), address(governance));
        relay.revokeRole(relay.DEFAULT_ADMIN_ROLE(), deployer);
        
        console.log("Transferred Relay Admin to Governance");
        
        // 3. Transfer Batcher Admin if applicable
        if (batcherAddr != address(0)) {
            MessageBatcher batcher = MessageBatcher(batcherAddr);
            batcher.grantRole(batcher.DEFAULT_ADMIN_ROLE(), address(governance));
            batcher.revokeRole(batcher.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Batcher Admin to Governance");
        }

        vm.stopBroadcast();
    }
}
