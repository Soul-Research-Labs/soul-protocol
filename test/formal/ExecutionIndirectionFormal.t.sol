// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/kernel/ExecutionIndirectionLayer.sol";

contract ExecutionIndirectionFormalTest is Test {
    ExecutionIndirectionLayer public kernel;
    
    // Roles
    bytes32 public constant INDIRECTION_ADMIN_ROLE = 0xc06ce89f9657b99059a90015a4538c0f25fff53ed687709dbb9386a471fbbe88;
    bytes32 public constant EXECUTOR_ROLE = 0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63;
    bytes32 public constant BACKEND_REGISTRAR_ROLE = 0x4f58ec39fe6d0e781e5b32159d8b275c3d7b6cc05cf79709bb1e1fbe221b5d45;

    function setUp() public {
        kernel = new ExecutionIndirectionLayer();
    }

    /**
     * @dev Prove that registerBackend only succeeds if caller has BACKEND_REGISTRAR_ROLE
     */
    function check_registerBackend_AccessControl(address caller, bytes32 bc, bytes32 ch, ExecutionIndirectionLayer.BackendType bt) public {
        vm.prank(caller);
        (bool success, ) = address(kernel).call(abi.encodeWithSelector(kernel.registerBackend.selector, bc, ch, bt));
        
        if (success) {
            assertTrue(kernel.hasRole(BACKEND_REGISTRAR_ROLE, caller));
        }
    }

    /**
     * @dev Prove that setIntentValidityPeriod only succeeds if caller has INDIRECTION_ADMIN_ROLE
     */
    function check_setIntentValidityPeriod_AccessControl(address caller, uint256 period) public {
        vm.prank(caller);
        (bool success, ) = address(kernel).call(abi.encodeWithSelector(kernel.setIntentValidityPeriod.selector, period));
        
        if (success) {
            assertTrue(kernel.hasRole(INDIRECTION_ADMIN_ROLE, caller));
        }
    }

    /**
     * @dev Prove that executeAndCommitResult only succeeds if caller has EXECUTOR_ROLE
     */
    function check_executeAndCommitResult_AccessControl(
        address caller,
        bytes32 ih,
        bytes32 rc,
        bytes32 sc,
        bytes32 dp,
        bytes calldata ep
    ) public {
        vm.prank(caller);
        (bool success, ) = address(kernel).call(abi.encodeWithSelector(kernel.executeAndCommitResult.selector, ih, rc, sc, dp, ep));
        
        if (success) {
            assertTrue(kernel.hasRole(EXECUTOR_ROLE, caller));
        }
    }
}
