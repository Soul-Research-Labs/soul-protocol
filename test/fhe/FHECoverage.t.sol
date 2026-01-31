// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/fhe/FHEGateway.sol";
import "../../contracts/fhe/FHEOracle.sol";
import "../../contracts/fhe/lib/FHEUtils.sol";

contract FHECoverageTest is Test {
    FHEGateway public gateway;
    FHEOracle public oracle;

    address public admin = address(this);
    address public mockCoprocessor = makeAddr("coprocessor");
    address public mockKMS = makeAddr("kms");

    function setUp() public {
        // Deploy FHEGateway
        // FHEScheme.TFHE is index 0 based on typical enum ordering, but will verify from file view
        gateway = new FHEGateway(mockCoprocessor, mockKMS, FHEUtils.FHEScheme.TFHE);

        // Deploy FHEOracle
        oracle = new FHEOracle(address(gateway), 3); // Threshold 3
    }

    function test_FHEGateway_Lifecycle() public {
        address handleCreator = makeAddr("creator");
        vm.startPrank(handleCreator);
        
        // Test handle creation
        vm.expectRevert(); // SecurityZoneMismatch
        gateway.createHandle(0, keccak256("INVALID_ZONE"));
        
        vm.stopPrank();
    }

    function test_FHEOracle_Lifecycle() public {
        // Register oracle
        vm.deal(admin, 100 ether);
        oracle.registerOracle{value: 10 ether}(keccak256("pubkey"));
        
        FHEOracle.OracleNode memory node = oracle.getOracle(admin);
        assertTrue(node.isActive);
        assertEq(node.stake, 10 ether);
    }
}
