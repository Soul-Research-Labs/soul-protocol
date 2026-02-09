// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

/**
 * @title Confirm Role Separation
 * @notice Post-deployment script to call confirmRoleSeparation() on core contracts.
 *         Must be executed by the multisig admin AFTER the deployer has renounced
 *         all operational roles (step 4 of DeployMainnet.s.sol).
 *
 * Prerequisites:
 *   - DeployMainnet.s.sol has been executed (contracts deployed, roles transferred)
 *   - The multisig admin holds DEFAULT_ADMIN_ROLE on both contracts
 *   - The multisig admin does NOT hold RELAYER_ROLE, CHALLENGER_ROLE (ProofHub)
 *   - The multisig admin does NOT hold DISPUTE_RESOLVER_ROLE, RECOVERY_ROLE, OPERATOR_ROLE (ZKBoundStateLocks)
 *
 * Usage (via Gnosis Safe Transaction Builder):
 *   forge script scripts/deploy/ConfirmRoleSeparation.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     -vvv
 *
 * Or generate calldata for Safe TX Builder:
 *   cast calldata "confirmRoleSeparation()" → use in Safe batch transaction
 */
contract ConfirmRoleSeparation is Script {
    function run() external {
        address proofHubAddr = vm.envAddress("PROOF_HUB_ADDRESS");
        address zkBoundStateLocksAddr = vm.envAddress("ZK_BOUND_STATE_LOCKS_ADDRESS");

        require(proofHubAddr != address(0), "PROOF_HUB_ADDRESS not set");
        require(zkBoundStateLocksAddr != address(0), "ZK_BOUND_STATE_LOCKS_ADDRESS not set");

        uint256 adminPK = vm.envUint("ADMIN_PRIVATE_KEY");
        address admin = vm.addr(adminPK);

        console.log("=== Confirm Role Separation ===");
        console.log("Admin (multisig):", admin);
        console.log("CrossChainProofHubV3:", proofHubAddr);
        console.log("ZKBoundStateLocks:", zkBoundStateLocksAddr);

        vm.startBroadcast(adminPK);

        // 1. Confirm role separation on CrossChainProofHubV3
        // Requires: caller has DEFAULT_ADMIN_ROLE, does NOT have RELAYER_ROLE or CHALLENGER_ROLE
        (bool success1, ) = proofHubAddr.call(
            abi.encodeWithSignature("confirmRoleSeparation()")
        );
        require(success1, "ProofHub confirmRoleSeparation() failed");
        console.log("CrossChainProofHubV3: role separation confirmed");

        // 2. Confirm role separation on ZKBoundStateLocks
        // Requires: caller has DEFAULT_ADMIN_ROLE, does NOT have DISPUTE_RESOLVER_ROLE,
        //           RECOVERY_ROLE, or OPERATOR_ROLE
        (bool success2, ) = zkBoundStateLocksAddr.call(
            abi.encodeWithSignature("confirmRoleSeparation()")
        );
        require(success2, "ZKBoundStateLocks confirmRoleSeparation() failed");
        console.log("ZKBoundStateLocks: role separation confirmed");

        vm.stopBroadcast();

        console.log("\n=== Role Separation Confirmed ===");
        console.log("Both contracts now enforce role separation.");
        console.log("Admin cannot hold operational roles going forward.");
    }
}
