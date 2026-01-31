// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/kernel/LinearStateManager.sol";

contract LinearStateFormalTest is Test {
    LinearStateManager public manager;
    
    // Roles
    bytes32 public constant STATE_ADMIN_ROLE = 0xf7054b28837a3e0f0fcdf0631d7a1f2c54f272601d37d24ed1fa836bd1c2ae94;
    bytes32 public constant KERNEL_ROLE = 0x6461d7edb0de6153faa1dbe72f8286821dd20b9e202b6351eb86ef5e04eaec51;
    bytes32 public constant BRIDGE_ROLE = 0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;

    function setUp() public {
        manager = new LinearStateManager();
    }

    function check_createGenesisState_AccessControl(address caller, bytes32 c, bytes32 tp, bytes32 ph) public {
        vm.prank(caller);
        (bool success, ) = address(manager).call(abi.encodeWithSelector(manager.createGenesisState.selector, c, tp, ph));
        if (success) {
            assertTrue(manager.hasRole(KERNEL_ROLE, caller));
        }
    }

    function check_registerPredicate_AccessControl(address caller, bytes32 ph) public {
        vm.prank(caller);
        (bool success, ) = address(manager).call(abi.encodeWithSelector(manager.registerPredicate.selector, ph));
        if (success) {
            assertTrue(manager.hasRole(STATE_ADMIN_ROLE, caller));
        }
    }

    function check_registerCrossDomainNullifier_AccessControl(address caller, bytes32 n, bytes32 sc, bytes32 ds, uint256 scid) public {
        vm.prank(caller);
        (bool success, ) = address(manager).call(abi.encodeWithSelector(manager.registerCrossDomainNullifier.selector, n, sc, ds, scid));
        if (success) {
            assertTrue(manager.hasRole(BRIDGE_ROLE, caller));
        }
    }

    /**
     * @dev Prove nullifier invariant: Once consumed, same nullifier cannot be used again
     */
    function check_DoubleSpend_Invariant(
        bytes32 oldC,
        bytes32 newC,
        bytes32 nullifier,
        bytes32 tp,
        bytes32 kpi,
        uint256 dcid
    ) public {
        // Setup initial state: oldC must be active
        vm.prank(address(this));
        manager.createGenesisState(oldC, tp, bytes32(0));
        
        vm.assume(oldC != newC);
        
        // First consumption
        vm.prank(address(this));
        try manager.consumeAndProduce(oldC, newC, nullifier, tp, kpi, dcid) {
            // If first succeeded, second MUST NOT succeed
            bytes32 otherOldC = keccak256("other");
            bytes32 otherNewC = keccak256("otherNew");
            vm.assume(otherOldC != oldC);
            vm.assume(otherOldC != newC);
            vm.assume(otherNewC != newC);
            vm.assume(otherNewC != oldC);
            
            vm.prank(address(this));
            manager.createGenesisState(otherOldC, tp, bytes32(0));
            
            vm.prank(address(this));
            (bool success2, ) = address(manager).call(abi.encodeWithSelector(manager.consumeAndProduce.selector, otherOldC, otherNewC, nullifier, tp, kpi, dcid));
            assertFalse(success2);
        } catch {
            // Fails vacuously
        }
    }
}
