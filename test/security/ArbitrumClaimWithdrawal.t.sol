// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";

/// @dev Mock Outbox that returns configurable results for isSpent and l2ToL1Sender
contract MockOutbox {
    mapping(uint256 => bool) public spentIndices;
    address public l2Sender;

    function setSpent(uint256 index, bool spent) external {
        spentIndices[index] = spent;
    }

    function setL2ToL1Sender(address sender) external {
        l2Sender = sender;
    }

    function isSpent(uint256 index) external view returns (bool) {
        return spentIndices[index];
    }

    function l2ToL1Sender() external view returns (address) {
        return l2Sender;
    }

    function l2ToL1Block() external pure returns (uint256) {
        return 0;
    }

    function l2ToL1Timestamp() external pure returns (uint256) {
        return 0;
    }

    function executeTransaction(
        bytes32[] calldata,
        uint256,
        address,
        address,
        uint256,
        uint256,
        uint256,
        uint256,
        bytes calldata
    ) external {}
}

/// @dev Mock Inbox for adapter constructor requirements
contract MockInbox {
    function calculateRetryableSubmissionFee(
        uint256,
        uint256
    ) external pure returns (uint256) {
        return 0.001 ether;
    }

    function createRetryableTicket(
        address,
        uint256,
        uint256,
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external payable returns (uint256) {
        return 1;
    }
}

/// @title ArbitrumClaimWithdrawalTest
/// @notice Security tests for the L2→L1 withdrawal finalization via outbox.isSpent()
contract ArbitrumClaimWithdrawalTest is Test {
    ArbitrumBridgeAdapter adapter;
    MockOutbox mockOutbox;
    MockInbox mockInbox;

    address admin = address(0xAD1);
    address operator = address(0x0E1);
    address executor = address(0xEC1);
    address recipient = makeAddr("recipient");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    address constant L2_TOKEN = address(0xA2);
    address constant L1_TOKEN = address(0xA1);
    uint256 constant ARB_ONE = 42161;
    uint256 constant CHALLENGE_PERIOD = 7 days;

    function setUp() public {
        mockOutbox = new MockOutbox();
        mockInbox = new MockInbox();

        adapter = new ArbitrumBridgeAdapter(admin);

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(EXECUTOR_ROLE, executor);
        adapter.grantRole(GUARDIAN_ROLE, admin);
        vm.stopPrank();

        // Configure rollup with mock outbox
        vm.prank(operator);
        adapter.configureRollup(
            ARB_ONE,
            address(mockInbox),
            address(mockOutbox),
            address(0xBB),
            address(0xCC),
            ArbitrumBridgeAdapter.RollupType.ARB_ONE
        );

        // Map a token
        vm.prank(operator);
        adapter.mapToken(L1_TOKEN, L2_TOKEN, ARB_ONE, 18);
    }

    /// @dev Helper to register a test withdrawal via the executor role
    function _registerWithdrawal(
        address _recipient,
        uint256 _amount,
        bytes32 _outputId
    ) internal returns (bytes32) {
        vm.prank(executor);
        return
            adapter.registerWithdrawal(
                address(0xA2BE),
                _recipient,
                L2_TOKEN,
                _amount,
                100, // l2BlockNumber
                50, // l1BatchNumber
                block.timestamp,
                _outputId,
                ARB_ONE
            );
    }

    /*//////////////////////////////////////////////////////////////
                   OUTBOX.ISSPENT() FINALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_claimWithdrawal_validOutboxProof() public {
        bytes32 outputId = keccak256("output1");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        // Warp past challenge period
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Mark the outbox index as spent (simulating Arbitrum proving)
        mockOutbox.setSpent(42, true);

        // Recipient claims directly
        vm.prank(recipient);
        adapter.claimWithdrawal(wId, new bytes32[](0), 42);

        // Verify finalization
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ArbitrumBridgeAdapter.TransferStatus status,
            ,
            ,
            uint256 claimedAt
        ) = adapter.withdrawals(wId);
        assertEq(
            uint256(status),
            uint256(ArbitrumBridgeAdapter.TransferStatus.FINALIZED)
        );
        assertGt(claimedAt, 0);
    }

    function test_claimWithdrawal_operatorClaims() public {
        bytes32 outputId = keccak256("output2");
        bytes32 wId = _registerWithdrawal(recipient, 2 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        mockOutbox.setSpent(99, true);

        // Operator claims on behalf of recipient
        vm.prank(operator);
        adapter.claimWithdrawal(wId, new bytes32[](0), 99);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ArbitrumBridgeAdapter.TransferStatus status,
            ,
            ,

        ) = adapter.withdrawals(wId);
        assertEq(
            uint256(status),
            uint256(ArbitrumBridgeAdapter.TransferStatus.FINALIZED)
        );
    }

    function test_claimWithdrawal_revertIfOutboxNotSpent() public {
        bytes32 outputId = keccak256("output3");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // outbox.isSpent(42) returns false — proof not yet available
        mockOutbox.setSpent(42, false);

        vm.prank(recipient);
        vm.expectRevert(ArbitrumBridgeAdapter.InvalidProof.selector);
        adapter.claimWithdrawal(wId, new bytes32[](0), 42);
    }

    function test_claimWithdrawal_revertIfChallengeNotExpired() public {
        bytes32 outputId = keccak256("output4");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        // Don't warp — still within challenge period
        mockOutbox.setSpent(42, true);

        vm.prank(recipient);
        vm.expectRevert(ArbitrumBridgeAdapter.ChallengeNotExpired.selector);
        adapter.claimWithdrawal(wId, new bytes32[](0), 42);
    }

    function test_claimWithdrawal_revertDoubleClaimSameOutput() public {
        bytes32 outputId = keccak256("outputDouble");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        mockOutbox.setSpent(42, true);

        vm.prank(recipient);
        adapter.claimWithdrawal(wId, new bytes32[](0), 42);

        // Second claim should revert — outputId already processed
        bytes32 wId2 = _registerWithdrawal(recipient, 1 ether, outputId);
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        vm.prank(recipient);
        vm.expectRevert(ArbitrumBridgeAdapter.OutputAlreadyProcessed.selector);
        adapter.claimWithdrawal(wId2, new bytes32[](0), 42);
    }

    function test_claimWithdrawal_revertUnauthorizedCaller() public {
        bytes32 outputId = keccak256("outputUnauth");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        mockOutbox.setSpent(42, true);

        // Random user (not recipient, not operator, not outbox) should be rejected
        address random = makeAddr("random");
        vm.prank(random);
        vm.expectRevert(ArbitrumBridgeAdapter.InvalidProof.selector);
        adapter.claimWithdrawal(wId, new bytes32[](0), 42);
    }

    function test_claimWithdrawal_outboxCallbackPath() public {
        bytes32 outputId = keccak256("outputCallback");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Outbox calls directly — l2ToL1Sender must be non-zero
        mockOutbox.setL2ToL1Sender(address(0xDEAD));

        vm.prank(address(mockOutbox));
        adapter.claimWithdrawal(wId, new bytes32[](0), 0);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ArbitrumBridgeAdapter.TransferStatus status,
            ,
            ,

        ) = adapter.withdrawals(wId);
        assertEq(
            uint256(status),
            uint256(ArbitrumBridgeAdapter.TransferStatus.FINALIZED)
        );
    }

    function test_claimWithdrawal_outboxCallbackRevertZeroSender() public {
        bytes32 outputId = keccak256("outputZeroSender");
        bytes32 wId = _registerWithdrawal(recipient, 1 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // l2ToL1Sender returns zero — invalid
        mockOutbox.setL2ToL1Sender(address(0));

        vm.prank(address(mockOutbox));
        vm.expectRevert(ArbitrumBridgeAdapter.InvalidProof.selector);
        adapter.claimWithdrawal(wId, new bytes32[](0), 0);
    }

    function test_claimWithdrawal_withdrawalStatsIncrement() public {
        bytes32 outputId = keccak256("outputStats");
        bytes32 wId = _registerWithdrawal(recipient, 5 ether, outputId);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        mockOutbox.setSpent(1, true);

        uint256 totalBefore = adapter.totalWithdrawals();
        uint256 valueBefore = adapter.totalValueWithdrawn();

        vm.prank(recipient);
        adapter.claimWithdrawal(wId, new bytes32[](0), 1);

        assertEq(adapter.totalWithdrawals(), totalBefore + 1);
        assertEq(adapter.totalValueWithdrawn(), valueBefore + 5 ether);
    }

    function test_claimWithdrawal_revertNonexistent() public {
        bytes32 fakeId = keccak256("nonexistent");

        vm.prank(recipient);
        vm.expectRevert(ArbitrumBridgeAdapter.WithdrawalNotFound.selector);
        adapter.claimWithdrawal(fakeId, new bytes32[](0), 0);
    }
}
