// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ChainlinkCCIPAdapter} from "../../contracts/crosschain/ChainlinkCCIPAdapter.sol";
import {IRouterClient} from "../../contracts/crosschain/ChainlinkCCIPAdapter.sol";

/// @title MockCCIPRouter
/// @notice Mock Chainlink CCIP Router for testing
contract MockCCIPRouter {
    uint256 public fixedFee = 0.01 ether;
    bool public shouldRevert;
    bytes32 public lastMessageId;
    uint256 public messageCount;

    function setFee(uint256 _fee) external {
        fixedFee = _fee;
    }

    function setShouldRevert(bool _revert) external {
        shouldRevert = _revert;
    }

    function ccipSend(
        uint64, // destinationChainSelector
        IRouterClient.EVM2AnyMessage calldata // message
    ) external payable returns (bytes32) {
        require(!shouldRevert, "Router: send failed");
        messageCount++;
        lastMessageId = keccak256(abi.encode(messageCount, block.timestamp));
        return lastMessageId;
    }

    function getFee(
        uint64, // destinationChainSelector
        IRouterClient.EVM2AnyMessage calldata // message
    ) external view returns (uint256) {
        return fixedFee;
    }
}

/**
 * @title ChainlinkCCIPAdapterTest
 * @notice Unit tests for ChainlinkCCIPAdapter
 */
contract ChainlinkCCIPAdapterTest is Test {
    ChainlinkCCIPAdapter public adapter;
    MockCCIPRouter public router;

    address public target = makeAddr("target");
    uint64 public constant DEST_SELECTOR = 5009297550715157269; // Arbitrum
    bytes public constant PAYLOAD = hex"deadbeef";

    function setUp() public {
        router = new MockCCIPRouter();
        adapter = new ChainlinkCCIPAdapter(address(router), DEST_SELECTOR);
    }

    // =========== bridgeMessage ===========

    /// @notice Happy path: bridge message with exact fee
    function test_bridgeMessage_exactFee() public {
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        bytes32 messageId = adapter.bridgeMessage{value: fee}(
            target,
            PAYLOAD,
            address(this)
        );
        assertTrue(messageId != bytes32(0), "Should return non-zero messageId");
        assertEq(router.messageCount(), 1);
    }

    /// @notice Bridge message with excess fee should refund
    function test_bridgeMessage_refundsExcess() public {
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        uint256 excess = 0.05 ether;
        uint256 balBefore = address(this).balance;

        adapter.bridgeMessage{value: fee + excess}(
            target,
            PAYLOAD,
            address(this)
        );

        // Balance should be reduced by exactly the fee (excess refunded)
        assertEq(
            address(this).balance,
            balBefore - fee,
            "Excess should be refunded"
        );
    }

    /// @notice Bridge message with insufficient fee should revert
    function test_bridgeMessage_insufficientFee() public {
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        vm.expectRevert("Insufficient fee");
        adapter.bridgeMessage{value: fee - 1}(target, PAYLOAD, address(this));
    }

    /// @notice Bridge message should revert if router fails
    function test_bridgeMessage_routerFails() public {
        router.setShouldRevert(true);
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        vm.expectRevert("Router: send failed");
        adapter.bridgeMessage{value: fee}(target, PAYLOAD, address(this));
    }

    // =========== estimateFee ===========

    /// @notice Fee estimation returns router fee
    function test_estimateFee_returnsRouterFee() public view {
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        assertEq(fee, router.fixedFee());
    }

    /// @notice Fee estimation changes when router fee changes
    function test_estimateFee_dynamic() public {
        router.setFee(0.1 ether);
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        assertEq(fee, 0.1 ether);
    }

    // =========== isMessageverified ===========

    /// @notice Unverified messages return false
    function test_isMessageverified_defaultFalse() public view {
        assertFalse(adapter.isMessageverified(bytes32(uint256(42))));
    }

    // =========== Immutable config ===========

    /// @notice Router and selector are correctly set
    function test_constructorConfig() public view {
        assertEq(address(adapter.i_router()), address(router));
        assertEq(adapter.destinationChainSelector(), DEST_SELECTOR);
    }

    /// @notice Owner is deployer
    function test_ownerIsDeployer() public view {
        assertEq(adapter.owner(), address(this));
    }

    // =========== Fuzz ===========

    /// @notice Fuzz: any payload can be bridged
    function testFuzz_bridgeMessage_anyPayload(bytes calldata payload) public {
        vm.assume(payload.length > 0 && payload.length < 10_000);
        uint256 fee = adapter.estimateFee(target, payload);
        bytes32 messageId = adapter.bridgeMessage{value: fee}(
            target,
            payload,
            address(this)
        );
        assertTrue(messageId != bytes32(0));
    }

    /// @notice Fuzz: fee always covers router cost
    function testFuzz_fee_coversRouterCost(uint256 routerFee) public {
        routerFee = bound(routerFee, 0, 1 ether);
        router.setFee(routerFee);
        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        assertEq(fee, routerFee);
    }

    // Required to receive refunds
    receive() external payable {}
}
