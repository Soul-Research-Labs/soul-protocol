// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GelatoRelayAdapter} from "../../contracts/relayer/GelatoRelayAdapter.sol";

/// @dev Mock Gelato Relay that returns predictable task IDs
contract MockGelatoRelay {
    bytes32 public lastTaskId;
    address public lastTarget;
    bytes public lastData;
    address public lastFeeToken;

    function callWithSyncFee(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external returns (bytes32) {
        lastTarget = _target;
        lastData = _data;
        lastFeeToken = _feeToken;
        lastTaskId = keccak256(
            abi.encodePacked(_target, _data, block.timestamp)
        );
        return lastTaskId;
    }

    function getFeeEstimate(
        address _target,
        bytes calldata _data,
        address _feeToken
    ) external pure returns (uint256) {
        return 0.001 ether;
    }
}

/// @dev Gelato Relay that always reverts
contract RevertingGelatoRelay {
    function callWithSyncFee(
        address,
        bytes calldata,
        address
    ) external pure returns (bytes32) {
        revert("Gelato: relay failed");
    }
}

contract GelatoRelayAdapterTest is Test {
    GelatoRelayAdapter public adapter;
    MockGelatoRelay public mockRelay;
    address public target;

    function setUp() public {
        mockRelay = new MockGelatoRelay();
        adapter = new GelatoRelayAdapter(address(mockRelay));
        target = makeAddr("target");
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsGelatoRelay() public view {
        assertEq(adapter.GELATO_RELAY(), address(mockRelay));
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(GelatoRelayAdapter.ZeroAddress.selector);
        new GelatoRelayAdapter(address(0));
    }

    function test_constructor_setsOwner() public view {
        assertEq(adapter.owner(), address(this));
    }

    /*//////////////////////////////////////////////////////////////
                        RELAY MESSAGE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_relayMessage_happyPath() public {
        bytes memory payload = abi.encodeWithSignature(
            "doSomething(uint256)",
            42
        );

        bytes32 taskId = adapter.relayMessage(target, payload, 200_000);

        // Task ID should be non-zero
        assertTrue(taskId != bytes32(0), "Task ID should be set");

        // Verify mock received correct parameters
        assertEq(mockRelay.lastTarget(), target);
        assertEq(mockRelay.lastData(), payload);
        assertEq(mockRelay.lastFeeToken(), adapter.ETH());
    }

    function test_relayMessage_revertsOnZeroTarget() public {
        bytes memory payload = hex"deadbeef";

        vm.expectRevert(GelatoRelayAdapter.InvalidTarget.selector);
        adapter.relayMessage(address(0), payload, 200_000);
    }

    function test_relayMessage_forwardsETHValue() public {
        bytes memory payload = hex"1234";
        vm.deal(address(this), 1 ether);

        // Should not revert when sending ETH
        adapter.relayMessage{value: 0.01 ether}(target, payload, 200_000);
    }

    function test_relayMessage_emptyPayload() public {
        // Empty payload is valid — some relayed calls have no data
        bytes32 taskId = adapter.relayMessage(target, "", 200_000);
        assertTrue(taskId != bytes32(0));
    }

    function test_relayMessage_propagatesGelatoRevert() public {
        RevertingGelatoRelay badRelay = new RevertingGelatoRelay();
        GelatoRelayAdapter badAdapter = new GelatoRelayAdapter(
            address(badRelay)
        );

        vm.expectRevert("Gelato: relay failed");
        badAdapter.relayMessage(target, hex"1234", 200_000);
    }

    /*//////////////////////////////////////////////////////////////
                          GET FEE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getFee_returnsFixedFee() public view {
        uint256 fee = adapter.getFee(200_000);
        assertEq(fee, 0.001 ether);
    }

    function test_getFee_ignoresGasLimit() public view {
        // Fee is fixed regardless of gas limit
        assertEq(adapter.getFee(0), adapter.getFee(1_000_000));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_relayMessage_arbitraryPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length <= 100_000); // Reasonable upper bound
        bytes32 taskId = adapter.relayMessage(target, payload, 200_000);
        assertTrue(taskId != bytes32(0));
        assertEq(mockRelay.lastData(), payload);
    }

    function testFuzz_relayMessage_arbitraryTarget(address _target) public {
        vm.assume(_target != address(0));
        bytes32 taskId = adapter.relayMessage(_target, hex"1234", 200_000);
        assertTrue(taskId != bytes32(0));
        assertEq(mockRelay.lastTarget(), _target);
    }

    function testFuzz_getFee_anyGasLimit(uint256 gasLimit) public view {
        uint256 fee = adapter.getFee(gasLimit);
        assertEq(fee, 0.001 ether, "Fee should always be 0.001 ether");
    }

    /*//////////////////////////////////////////////////////////////
                        ETH CONSTANT TEST
    //////////////////////////////////////////////////////////////*/

    function test_ethConstant() public view {
        assertEq(
            adapter.ETH(),
            0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE,
            "ETH sentinel must match Gelato convention"
        );
    }
}
