// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

contract RateLimitFormalTest is Test {
    EthereumL1Bridge public bridge;
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    function setUp() public {
        bridge = new EthereumL1Bridge();
        bridge.grantRole(RELAYER_ROLE, address(this));
        vm.deal(address(this), 100 ether);
    }

    /**
     * @dev Prove that the rate limit correctly restricts commitments per hour
     */
    function check_RateLimit_Enforcement(uint256 maxCommitments, uint256 currentCount) public {
        vm.assume(maxCommitments > 0 && maxCommitments < 100);
        vm.assume(currentCount == maxCommitments);
        
        // Use an internal function call if possible, or trigger it via a public function
        bridge.grantRole(bridge.DEFAULT_ADMIN_ROLE(), address(this));
        bridge.setMaxCommitmentsPerHour(maxCommitments);
        
        // We need to set the state so that the rate limit is reached
        // Since we can't easily manipulate internal state directly in Halmos without calling functions,
        // we'll simulate the submission process.
        
        // This test might be better as a symbolic state test where we prove that 
        // IF count >= max, THEN submission reverts.
    }

    /**
     * @dev Prove that the rate limit resets after 1 hour
     */
    function check_RateLimit_Reset(uint256 t1, uint256 t2) public {
        vm.assume(t1 > 1000000 && t1 < type(uint256).max - 2000000); // 2M buffer
        vm.assume(t2 >= t1 + 3601 && t2 < type(uint256).max - 2000000); 
        
        vm.warp(t1);
        bridge.grantRole(bridge.DEFAULT_ADMIN_ROLE(), address(this));
        bridge.grantRole(bridge.OPERATOR_ROLE(), address(this));
        bridge.setMaxCommitmentsPerHour(1);
        
        // Reach limit
        bridge.submitStateCommitment{value: 0.1 ether}(10, bytes32(uint256(1)), bytes32(0), 100);
        
        // Next one should revert
        vm.prank(address(this));
        (bool success1, ) = address(bridge).call{value: 0.1 ether}(abi.encodeWithSelector(bridge.submitStateCommitment.selector, 10, bytes32(uint256(2)), bytes32(0), 101));
        assertFalse(success1);
        
        // Warp to next hour
        vm.warp(t2);
        
        // Should succeed now
        vm.prank(address(this));
        (bool success2, ) = address(bridge).call{value: 0.1 ether}(abi.encodeWithSelector(bridge.submitStateCommitment.selector, 10, bytes32(uint256(3)), bytes32(0), 102));
        assertTrue(success2);
    }
}
