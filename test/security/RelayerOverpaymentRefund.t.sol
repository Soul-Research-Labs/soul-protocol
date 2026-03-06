// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";
import {IDecentralizedRelayerRegistry} from "../../contracts/interfaces/IDecentralizedRelayerRegistry.sol";

/// @dev Contract that rejects ETH transfers — used to test refund failure path
contract RefundRejecter {
    DecentralizedRelayerRegistry public registry;

    constructor(DecentralizedRelayerRegistry _registry) {
        registry = _registry;
    }

    function registerWithOverpayment() external payable {
        registry.register{value: msg.value}();
    }

    // Reject all ETH transfers
    receive() external payable {
        revert("no refunds");
    }
}

/// @dev Contract that accepts ETH — for comparison
contract RefundAccepter {
    DecentralizedRelayerRegistry public registry;

    constructor(DecentralizedRelayerRegistry _registry) {
        registry = _registry;
    }

    function registerWithOverpayment() external payable {
        registry.register{value: msg.value}();
    }

    function registerFromOwnBalance(uint256 amount) external {
        registry.register{value: amount}();
    }

    receive() external payable {}
}

/// @title RelayerOverpaymentRefundTest
/// @notice Security tests for ETH overpayment refund in register()
contract RelayerOverpaymentRefundTest is Test {
    DecentralizedRelayerRegistry public registry;
    address public admin = address(this);
    address public relayer = makeAddr("relayer");

    uint256 constant MIN_STAKE = 10 ether;

    function setUp() public {
        registry = new DecentralizedRelayerRegistry(admin);
        vm.deal(relayer, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
               OVERPAYMENT REFUND — HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_register_exactStakeNoRefund() public {
        uint256 balBefore = relayer.balance;

        vm.prank(relayer);
        registry.register{value: MIN_STAKE}();

        // No excess, so balance decreases by exactly MIN_STAKE
        assertEq(relayer.balance, balBefore - MIN_STAKE);
        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, MIN_STAKE);
        assertTrue(isRegistered);
    }

    function test_register_overpaymentRefunded() public {
        uint256 overpayment = 5 ether;
        uint256 sent = MIN_STAKE + overpayment;
        uint256 balBefore = relayer.balance;

        vm.prank(relayer);
        registry.register{value: sent}();

        // Relayer balance should only decrease by MIN_STAKE (excess refunded)
        assertEq(relayer.balance, balBefore - MIN_STAKE);

        // Stake should be exactly MIN_STAKE, not the full sent amount
        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer);
        assertEq(stake, MIN_STAKE);
        assertTrue(isRegistered);
    }

    function test_register_contractBalanceOnlyKeepsStake() public {
        uint256 sent = MIN_STAKE + 7 ether;

        vm.prank(relayer);
        registry.register{value: sent}();

        // Registry should only hold MIN_STAKE
        assertEq(address(registry).balance, MIN_STAKE);
    }

    function test_register_largeOverpayment() public {
        uint256 sent = 50 ether; // 40 ether excess
        uint256 balBefore = relayer.balance;

        vm.prank(relayer);
        registry.register{value: sent}();

        assertEq(relayer.balance, balBefore - MIN_STAKE);
        assertEq(address(registry).balance, MIN_STAKE);
    }

    /*//////////////////////////////////////////////////////////////
               OVERPAYMENT REFUND — FAILURE PATH
    //////////////////////////////////////////////////////////////*/

    function test_register_refundFailureReverts() public {
        RefundRejecter rejecter = new RefundRejecter(registry);
        vm.deal(address(rejecter), 20 ether);

        // The contract rejects ETH, so refund should cause TransferFailed revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IDecentralizedRelayerRegistry.TransferFailed.selector,
                address(rejecter),
                5 ether
            )
        );
        rejecter.registerWithOverpayment{value: 15 ether}();
    }

    function test_register_refundSucceedsForAcceptingContract() public {
        RefundAccepter accepter = new RefundAccepter(registry);
        vm.deal(address(accepter), 20 ether);

        uint256 balBefore = address(accepter).balance;
        accepter.registerFromOwnBalance(15 ether);

        // Contract balance should decrease by only MIN_STAKE (overpayment refunded)
        assertEq(address(accepter).balance, balBefore - MIN_STAKE);
    }

    /*//////////////////////////////////////////////////////////////
               FUZZ: OVERPAYMENT ACCOUNTING
    //////////////////////////////////////////////////////////////*/

    function testFuzz_register_overpaymentAccounting(uint256 extra) public {
        // Bound extra to reasonable range
        extra = bound(extra, 0, 90 ether);
        uint256 sent = MIN_STAKE + extra;

        vm.deal(relayer, sent + 1); // +1 for gas headroom on foundry
        uint256 balBefore = relayer.balance;

        vm.prank(relayer);
        registry.register{value: sent}();

        // Invariant: relayer balance + registry balance == initial balance
        assertEq(relayer.balance + address(registry).balance, balBefore);
        // Registry only keeps MIN_STAKE
        assertEq(address(registry).balance, MIN_STAKE);
        // Relayer keeps the excess
        assertEq(relayer.balance, balBefore - MIN_STAKE);
    }

    function testFuzz_register_stakeAlwaysMinStake(uint256 sent) public {
        sent = bound(sent, MIN_STAKE, 100 ether);

        address fuzzRelayer = makeAddr(string(abi.encodePacked("fuzz", sent)));
        vm.deal(fuzzRelayer, sent);

        vm.prank(fuzzRelayer);
        registry.register{value: sent}();

        (uint256 stake, , , bool isRegistered) = registry.relayers(fuzzRelayer);
        assertEq(stake, MIN_STAKE);
        assertTrue(isRegistered);
    }
}
