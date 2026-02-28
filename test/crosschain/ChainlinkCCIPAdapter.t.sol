// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    // =========== isMessageVerified ===========

    /// @notice Unverified messages return false
    function test_isMessageVerified_defaultFalse() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(42))));
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

// ═══════════════════════════════════════════════════════════════
//  TOKEN TRANSFER TESTS
// ═══════════════════════════════════════════════════════════════

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Minimal ERC-20 for testing token transfers
contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000e18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title ChainlinkCCIPAdapterTokenTest
 * @notice Tests for bridgeMessageWithTokens and estimateFeeWithTokens
 */
contract ChainlinkCCIPAdapterTokenTest is Test {
    ChainlinkCCIPAdapter public adapter;
    MockCCIPRouter public router;
    MockToken public token;

    address public target = makeAddr("target");
    address public alice = makeAddr("alice");
    uint64 public constant DEST_SELECTOR = 5009297550715157269;
    bytes public constant PAYLOAD = hex"cafebabe";

    function setUp() public {
        router = new MockCCIPRouter();
        adapter = new ChainlinkCCIPAdapter(address(router), DEST_SELECTOR);

        token = new MockToken();
        // Transfer tokens to alice
        token.transfer(alice, 100e18);
    }

    // =========== bridgeMessageWithTokens ===========

    function test_bridgeWithTokens_happyPath() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10e18;

        vm.startPrank(alice);
        token.approve(address(adapter), 10e18);

        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        vm.deal(alice, fee);

        bytes32 messageId = adapter.bridgeMessageWithTokens{value: fee}(
            target,
            PAYLOAD,
            tokens,
            amounts
        );
        vm.stopPrank();

        assertTrue(messageId != bytes32(0), "Should return valid messageId");
        // Tokens should have been pulled from alice
        assertEq(
            token.balanceOf(alice),
            90e18,
            "Alice balance should decrease by 10 tokens"
        );
    }

    function test_bridgeWithTokens_mismatchedArraysReverts() public {
        address[] memory tokens = new address[](2);
        tokens[0] = address(token);
        tokens[1] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10e18;

        vm.prank(alice);
        vm.expectRevert(ChainlinkCCIPAdapter.TokenArrayLengthMismatch.selector);
        adapter.bridgeMessageWithTokens(target, PAYLOAD, tokens, amounts);
    }

    function test_bridgeWithTokens_zeroTokenAddressReverts() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10e18;

        vm.startPrank(alice);
        vm.expectRevert(ChainlinkCCIPAdapter.ZeroTokenAddress.selector);
        adapter.bridgeMessageWithTokens(target, PAYLOAD, tokens, amounts);
        vm.stopPrank();
    }

    function test_bridgeWithTokens_zeroAmountReverts() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 0;

        vm.startPrank(alice);
        vm.expectRevert(ChainlinkCCIPAdapter.ZeroTokenAmount.selector);
        adapter.bridgeMessageWithTokens(target, PAYLOAD, tokens, amounts);
        vm.stopPrank();
    }

    function test_bridgeWithTokens_tooManyTokensReverts() public {
        address[] memory tokens = new address[](6); // MAX_TOKENS_PER_MESSAGE = 5
        uint256[] memory amounts = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokens[i] = address(token);
            amounts[i] = 1e18;
        }

        vm.startPrank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChainlinkCCIPAdapter.MaxTokensExceeded.selector,
                6,
                5
            )
        );
        adapter.bridgeMessageWithTokens(target, PAYLOAD, tokens, amounts);
        vm.stopPrank();
    }

    // =========== estimateFeeWithTokens ===========

    function test_estimateFeeWithTokens_returnsRouterFee() public view {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10e18;

        uint256 fee = adapter.estimateFeeWithTokens(
            target,
            PAYLOAD,
            tokens,
            amounts
        );
        assertEq(fee, router.fixedFee(), "Fee should match router fee");
    }

    function test_estimateFeeWithTokens_mismatchedArraysReverts() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10e18;
        amounts[1] = 5e18;

        vm.expectRevert(ChainlinkCCIPAdapter.TokenArrayLengthMismatch.selector);
        adapter.estimateFeeWithTokens(target, PAYLOAD, tokens, amounts);
    }

    // =========== Multiple tokens ===========

    function test_bridgeWithTokens_multipleTokens() public {
        MockToken token2 = new MockToken();
        token2.transfer(alice, 50e18);

        address[] memory tokens = new address[](2);
        tokens[0] = address(token);
        tokens[1] = address(token2);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 5e18;
        amounts[1] = 3e18;

        vm.startPrank(alice);
        token.approve(address(adapter), 5e18);
        token2.approve(address(adapter), 3e18);

        uint256 fee = adapter.estimateFee(target, PAYLOAD);
        vm.deal(alice, fee);

        bytes32 messageId = adapter.bridgeMessageWithTokens{value: fee}(
            target,
            PAYLOAD,
            tokens,
            amounts
        );
        vm.stopPrank();

        assertTrue(messageId != bytes32(0));
        assertEq(token.balanceOf(alice), 95e18);
        assertEq(token2.balanceOf(alice), 47e18);
    }

    receive() external payable {}
}
