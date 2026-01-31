// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/LayerZeroBridgeAdapter.sol";
import "../../contracts/crosschain/StarknetBridgeAdapter.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

contract BridgeCoverageTest is Test {
    LayerZeroBridgeAdapter public lzAdapter;
    StarknetBridgeAdapter public starknetAdapter;
    EthereumL1Bridge public ethBridge;

    address public admin = address(this);
    address public mockLzEndpoint = makeAddr("lzEndpoint");
    address public mockStarknetCore = makeAddr("starknetCore");
    address public mockStarknetMessaging = makeAddr("starknetMessaging");

    function setUp() public {
        // Deploy EthereumL1Bridge
        ethBridge = new EthereumL1Bridge();

        // Deploy StarknetBridgeAdapter
        starknetAdapter = new StarknetBridgeAdapter(admin);
        
        // Deploy LayerZeroBridgeAdapter
        lzAdapter = new LayerZeroBridgeAdapter();
    }

    function test_EthereumL1Bridge_Lifecycle() public {
        // Test basic config
        vm.expectEmit(true, true, false, true);
        emit EthereumL1Bridge.L2ChainUpdated(42161, false);
        ethBridge.setChainEnabled(42161, false);
        
        // Test deposit
        bytes32 commitment = keccak256("commitment");
        ethBridge.depositETH{value: 1 ether}(10, commitment);
    }

    function test_StarknetBridgeAdapter_Config() public {
        starknetAdapter.configure(
            mockStarknetCore,
            mockStarknetMessaging,
            123456 // l2BridgeAddress
        );
        
        (address core, address messaging, uint256 l2Addr, bool active) = starknetAdapter.config();
        assertEq(core, mockStarknetCore);
        assertEq(messaging, mockStarknetMessaging);
        assertEq(l2Addr, 123456);
        assertTrue(active);
    }

    function test_LayerZeroBridgeAdapter_Config() public {
         // Setup endpoint
         lzAdapter.setEndpoint(mockLzEndpoint, 1);
         assertEq(lzAdapter.lzEndpoint(), mockLzEndpoint);
         assertEq(lzAdapter.localEid(), 1);
    }
}
