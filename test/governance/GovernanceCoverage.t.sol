// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/governance/SoulMultiSigGovernance.sol";
import "../../contracts/governance/SoulTimelock.sol";

contract GovernanceCoverageTest is Test {
    SoulMultiSigGovernance public governance;
    SoulTimelock public timelock;

    address public admin = address(this);
    address[] public proposers;
    address[] public executors;

    function setUp() public {
        // Setup arrays
        proposers.push(admin);
        executors.push(admin);

        // Deploy MultiSig Governance
        governance = new SoulMultiSigGovernance(admin);

        // Deploy Timelock
        // minDelay = 1 hour (3600), emergencyDelay = 1 hour, confirmations = 1
        timelock = new SoulTimelock(3600, 3600, 1, proposers, executors, admin);
    }

    function test_SoulMultiSigGovernance_Lifecycle() public {
        assertTrue(governance.hasRole(governance.SUPER_ADMIN_ROLE(), admin));
        // Check default config
        (uint256 reqSigs, uint256 members, bool active) = governance
            .roleConfigs(governance.ADMIN_ROLE());
        assertTrue(active);
        assertEq(reqSigs, 3);
    }

    function test_SoulTimelock_Lifecycle() public {
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), admin));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), admin));
        assertEq(timelock.minDelay(), 3600);
    }
}
