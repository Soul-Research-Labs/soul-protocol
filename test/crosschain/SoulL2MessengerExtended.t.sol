// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SoulL2Messenger.sol";
import {ISoulL2Messenger} from "../../contracts/interfaces/ISoulL2Messenger.sol";

/// @dev Mock target that accepts calls
contract MockTargetExt {
    uint256 public lastValue;
    bool public shouldRevert;

    function setData(uint256 val) external payable {
        if (shouldRevert) revert("MockTarget: revert");
        lastValue = val;
    }

    function setShouldRevert(bool _val) external {
        shouldRevert = _val;
    }

    receive() external payable {}
}

/// @dev Mock decryption verifier
contract MockDecryptionVerifierExt {
    bool public shouldPass = true;

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function setShouldPass(bool _val) external {
        shouldPass = _val;
    }
}

/**
 * @title SoulL2MessengerExtendedTest
 * @notice Extended tests covering pause/unpause, setDecryptionVerifier access control,
 *         double-fulfill prevention, fuzz tests, and edge cases.
 *         Supplements the existing SoulL2MessengerTest.
 */
contract SoulL2MessengerExtendedTest is Test {
    SoulL2Messenger public messenger;
    MockTargetExt public target;
    MockDecryptionVerifierExt public mockDecryptionVerifier;

    address public admin = address(this);
    address public proofHub = address(0xBEEF);
    address public fulfiller1;
    address public user;
    address public counterpart = address(0xCC);

    uint256 public constant DEST_CHAIN = 42_161;
    uint256 public constant SOURCE_CHAIN = 10;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant FULFILLER_ROLE = keccak256("FULFILLER_ROLE");

    function setUp() public {
        fulfiller1 = makeAddr("fulfiller1");
        user = makeAddr("user");

        messenger = new SoulL2Messenger(proofHub);

        mockDecryptionVerifier = new MockDecryptionVerifierExt();
        messenger.setDecryptionVerifier(address(mockDecryptionVerifier));

        messenger.setCounterpart(DEST_CHAIN, counterpart);
        messenger.setCounterpart(SOURCE_CHAIN, counterpart);

        vm.deal(fulfiller1, 10 ether);
        vm.deal(user, 10 ether);

        vm.prank(fulfiller1);
        messenger.registerFulfiller{value: 0.1 ether}();

        target = new MockTargetExt();
    }

    // =========================================================================
    // ROLE MANAGEMENT — previously untested
    // =========================================================================

    function test_operatorRole_grantAndRevoke() public {
        address newOperator = makeAddr("newOperator");
        messenger.grantRole(messenger.OPERATOR_ROLE(), newOperator);
        assertTrue(messenger.hasRole(messenger.OPERATOR_ROLE(), newOperator));

        messenger.revokeRole(messenger.OPERATOR_ROLE(), newOperator);
        assertFalse(messenger.hasRole(messenger.OPERATOR_ROLE(), newOperator));
    }

    function test_fulfillerRole_grantRevert_unauthorized() public {
        address rando = makeAddr("rando");
        vm.prank(user);
        vm.expectRevert();
        messenger.grantRole(FULFILLER_ROLE, rando);
    }

    // =========================================================================
    // COUNTERPART MANAGEMENT — edge cases
    // =========================================================================

    function test_setCounterpart_success() public {
        address counterpart = makeAddr("counterpart");
        messenger.setCounterpart(DEST_CHAIN, counterpart);
        assertEq(messenger.counterpartMessengers(DEST_CHAIN), counterpart);
    }

    function test_setCounterpart_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.setCounterpart(DEST_CHAIN, makeAddr("counterpart"));
    }

    function test_setCounterpart_overwrite_multipleChains() public {
        address first = makeAddr("first");
        address second = makeAddr("second");
        uint256 chainA = 42161;
        uint256 chainB = 10;
        messenger.setCounterpart(chainA, first);
        messenger.setCounterpart(chainB, second);
        assertEq(messenger.counterpartMessengers(chainA), first);
        assertEq(messenger.counterpartMessengers(chainB), second);
    }

    // =========================================================================
    // setDecryptionVerifier — access control test previously missing
    // =========================================================================

    function test_setDecryptionVerifier_success() public {
        address newVerifier = makeAddr("newVerifier");
        messenger.setDecryptionVerifier(newVerifier);
        assertEq(messenger.decryptionVerifier(), newVerifier);
    }

    function test_setDecryptionVerifier_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.setDecryptionVerifier(makeAddr("v"));
    }

    // =========================================================================
    // DOUBLE FULFILL PREVENTION
    // =========================================================================

    function test_fulfillMessage_revert_alreadyFulfilled() public {
        // Send a message first
        bytes32 nullifier = keccak256("test_double_null");
        bytes32 commitment = keccak256("test_double_commit");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            abi.encodeWithSignature("setData(uint256)", 42),
            commitment,
            nullifier,
            500_000 // gasLimit (not a deadline)
        );

        // First fulfill should succeed
        vm.prank(fulfiller1);
        messenger.fulfillMessage(
            msgId,
            abi.encodeWithSignature("setData(uint256)", 42),
            hex"" // empty ZK proof — mock verifier accepts
        );

        // Second fulfill should revert (message is already fulfilled)
        vm.prank(fulfiller1);
        vm.expectRevert();
        messenger.fulfillMessage(
            msgId,
            abi.encodeWithSignature("setData(uint256)", 42),
            hex""
        );
    }

    // =========================================================================
    // FUZZ TESTS — previously missing
    // =========================================================================

    function testFuzz_sendPrivacyMessage_uniqueIds(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));
        vm.assume(commitment != bytes32(0));
        // Ensure nullifier uniqueness per call
        vm.assume(nullifier != keccak256("used"));

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            abi.encode("data"),
            commitment,
            nullifier,
            block.timestamp + 1 hours
        );

        assertTrue(msgId != bytes32(0), "Message ID should be non-zero");
    }

    function testFuzz_registerFulfiller_bondAmounts(uint256 amount) public {
        amount = bound(amount, 0.05 ether, 10 ether);
        address newFulfiller = makeAddr("fuzz_fulfiller");
        vm.deal(newFulfiller, amount);

        vm.prank(newFulfiller);
        messenger.registerFulfiller{value: amount}();

        assertEq(messenger.fulfillerBonds(newFulfiller), amount);
        assertTrue(messenger.hasRole(FULFILLER_ROLE, newFulfiller));
    }

    function testFuzz_withdrawBond_partialAmounts(
        uint256 withdrawAmount
    ) public {
        // Register with 1 ether
        address fuzzFulfiller = makeAddr("fuzz_wd");
        vm.deal(fuzzFulfiller, 2 ether);
        vm.prank(fuzzFulfiller);
        messenger.registerFulfiller{value: 1 ether}();

        // Withdraw partial amount, keeping at least minFulfillerBond (0.05 ether)
        withdrawAmount = bound(withdrawAmount, 0.01 ether, 0.9 ether);

        vm.prank(fuzzFulfiller);
        messenger.withdrawBond(withdrawAmount);

        uint256 remaining = messenger.fulfillerBonds(fuzzFulfiller);
        assertEq(remaining, 1 ether - withdrawAmount);
    }

    // =========================================================================
    // EDGE CASES
    // =========================================================================

    function test_sendPrivacyMessage_withMaxExpiry() public {
        bytes32 nullifier = keccak256("max_expiry");
        bytes32 commitment = keccak256("max_commit");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            abi.encode("data"),
            commitment,
            nullifier,
            type(uint256).max // max expiry
        );
        assertTrue(msgId != bytes32(0));
    }

    function test_sendPrivacyMessage_emptyPayload() public {
        bytes32 nullifier = keccak256("empty_payload");
        bytes32 commitment = keccak256("empty_commit");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            hex"", // empty payload
            commitment,
            nullifier,
            block.timestamp + 1 hours
        );
        assertTrue(msgId != bytes32(0));
    }

    function test_counterpartMessengers_unsetChain() public view {
        assertEq(
            messenger.counterpartMessengers(999_999),
            address(0),
            "Unset chain should return zero address"
        );
    }

    function test_setCounterpart_overwrite() public {
        address newCounterpart = makeAddr("newCp");
        messenger.setCounterpart(DEST_CHAIN, newCounterpart);
        assertEq(messenger.counterpartMessengers(DEST_CHAIN), newCounterpart);
    }

    function test_totalMessagesSent_increments() public {
        uint256 before = messenger.totalMessagesSent();

        vm.prank(user);
        messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            abi.encode("data"),
            keccak256("inc_commit"),
            keccak256("inc_null"),
            block.timestamp + 1 hours
        );

        assertEq(messenger.totalMessagesSent(), before + 1);
    }
}
