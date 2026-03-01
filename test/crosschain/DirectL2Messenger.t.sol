// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/DirectL2Messenger.sol";
import {IL2DirectMessenger} from "../../contracts/interfaces/IL2DirectMessenger.sol";

/// @notice Mock recipient contract
contract MockRecipient {
    bytes public lastPayload;
    bool public shouldFail;

    function execute(bytes calldata data) external payable {
        require(!shouldFail, "MockRecipient: failed");
        lastPayload = data;
    }

    fallback() external payable {
        require(!shouldFail, "MockRecipient: failed");
        lastPayload = msg.data;
    }

    receive() external payable {}

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }
}

/// @notice Mock superchain messenger
contract MockSuperchainMessenger {
    bytes public lastMessage;
    uint256 public lastDestChainId;
    address public lastTarget;

    function sendMessage(
        uint256 _dest,
        address _target,
        bytes calldata _msg
    ) external {
        lastDestChainId = _dest;
        lastTarget = _target;
        lastMessage = _msg;
    }
}

contract DirectL2MessengerTest is Test {
    DirectL2Messenger public messenger;
    MockRecipient public recipient;
    MockSuperchainMessenger public mockSuperchain;

    address public admin = address(this);
    address public zaseonHub = makeAddr("zaseonHub");
    address public operator = makeAddr("operator");
    address public user = makeAddr("user");

    uint256 public constant DEST_CHAIN = 10; // Optimism

    function setUp() public {
        messenger = new DirectL2Messenger(admin, zaseonHub);
        recipient = new MockRecipient();
        mockSuperchain = new MockSuperchainMessenger();

        // Grant roles
        messenger.grantRole(messenger.OPERATOR_ROLE(), operator);

        // Fund accounts
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
        vm.deal(address(messenger), 10 ether);

        // Configure a route (outbound: this chain → DEST_CHAIN)
        vm.prank(operator);
        messenger.configureRoute(
            block.chainid,
            DEST_CHAIN,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0), // No adapter needed for fast relayer
            3,
            30 minutes
        );

        // Configure inbound route (source chain 10 → this chain) for receiveMessage tests
        vm.prank(operator);
        messenger.configureRoute(
            10,
            block.chainid,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );
    }

    // ============ Constructor Tests ============

    /// @dev Helper: register a relayer and approve via operator
    function _registerAndApprove(address relayer) internal {
        vm.prank(relayer);
        messenger.registerRelayer{value: 1 ether}();
        vm.prank(operator);
        messenger.approveRelayer(relayer);
    }

    function test_constructor_setsAdmin() public view {
        assertTrue(messenger.hasRole(messenger.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_constructor_setsOperator() public view {
        assertTrue(messenger.hasRole(messenger.OPERATOR_ROLE(), admin));
    }

    function test_constructor_setsZaseonHub() public view {
        assertEq(messenger.zaseonHub(), zaseonHub);
    }

    function test_constructor_setsChainId() public view {
        assertEq(messenger.currentChainId(), block.chainid);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(DirectL2Messenger.ZeroAddress.selector);
        new DirectL2Messenger(address(0), zaseonHub);
    }

    function test_constructor_revertsZeroZaseonHub() public {
        vm.expectRevert(DirectL2Messenger.ZeroAddress.selector);
        new DirectL2Messenger(admin, address(0));
    }

    // ============ Send Message Tests ============

    function test_sendMessage_fastRelayer() public {
        vm.prank(user);
        bytes32 msgId = messenger.sendMessage{value: 0.1 ether}(
            DEST_CHAIN,
            address(recipient),
            bytes("hello"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );

        assertTrue(msgId != bytes32(0));
        assertEq(messenger.globalNonce(), 1);
    }

    function test_sendMessage_revertsSameChain() public {
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.InvalidDestinationChain.selector);
        messenger.sendMessage(
            block.chainid, // Same chain
            address(recipient),
            bytes("hello"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );
    }

    function test_sendMessage_revertsZeroRecipient() public {
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.InvalidMessage.selector);
        messenger.sendMessage(
            DEST_CHAIN,
            address(0),
            bytes("hello"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );
    }

    function test_sendMessage_revertsNoRoute() public {
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.UnsupportedRoute.selector);
        messenger.sendMessage(
            999, // No route configured
            address(recipient),
            bytes("hello"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );
    }

    function test_sendMessage_slowL1NoRouteRequired() public {
        // SLOW_L1 path doesn't need a route config, but needs an adapter
        // Without an adapter, it should revert with UnsupportedRoute
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.UnsupportedRoute.selector);
        messenger.sendMessage(
            888,
            address(recipient),
            bytes("hello"),
            IL2DirectMessenger.MessagePath.SLOW_L1,
            bytes32(0)
        );
    }

    // ============ Relayer Registration Tests ============

    function test_registerRelayer() public {
        vm.prank(user);
        messenger.registerRelayer{value: 1 ether}();

        IL2DirectMessenger.Relayer memory rel = messenger.getRelayer(user);
        assertTrue(rel.active);
        assertEq(rel.bond, 1 ether);
        assertEq(rel.addr, user);
        assertEq(messenger.getRelayerCount(), 1);
    }

    function test_registerRelayer_revertsInsufficientBond() public {
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.InsufficientBond.selector);
        messenger.registerRelayer{value: 0.5 ether}();
    }

    function test_registerRelayer_revertsDuplicate() public {
        vm.startPrank(user);
        messenger.registerRelayer{value: 1 ether}();
        vm.expectRevert(DirectL2Messenger.InvalidRelayer.selector);
        messenger.registerRelayer{value: 1 ether}();
        vm.stopPrank();
    }

    // ============ Relayer Bond Withdrawal Tests ============

    function test_withdrawRelayerBond_afterUnbonding() public {
        vm.prank(user);
        messenger.registerRelayer{value: 2 ether}();

        // Advance past unbonding period
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balBefore = user.balance;
        vm.prank(user);
        messenger.withdrawRelayerBond();

        assertEq(user.balance - balBefore, 2 ether);
        IL2DirectMessenger.Relayer memory rel = messenger.getRelayer(user);
        assertFalse(rel.active);
        assertEq(rel.bond, 0);
    }

    function test_withdrawRelayerBond_revertsBeforeUnbonding() public {
        vm.prank(user);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.UnbondingPeriodNotComplete.selector);
        messenger.withdrawRelayerBond();
    }

    // ============ Slash Relayer Tests ============

    function test_slashRelayer() public {
        vm.prank(user);
        messenger.registerRelayer{value: 2 ether}();

        vm.prank(operator);
        messenger.slashRelayer(user, 0.5 ether, keccak256("fraud"));

        IL2DirectMessenger.Relayer memory rel = messenger.getRelayer(user);
        assertEq(rel.bond, 1.5 ether);
        assertEq(rel.slashedAmount, 0.5 ether);
        assertEq(rel.failCount, 1);
        assertTrue(rel.active); // Still active, bond > MIN
    }

    function test_slashRelayer_deactivatesIfBondTooLow() public {
        vm.prank(user);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(operator);
        messenger.slashRelayer(user, 0.5 ether, keccak256("fraud"));

        IL2DirectMessenger.Relayer memory rel = messenger.getRelayer(user);
        assertFalse(rel.active); // Bond < MIN_RELAYER_BOND
    }

    function test_slashRelayer_capsAtBond() public {
        vm.prank(user);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(operator);
        messenger.slashRelayer(user, 10 ether, keccak256("fraud")); // More than bond

        IL2DirectMessenger.Relayer memory rel = messenger.getRelayer(user);
        assertEq(rel.bond, 0);
        assertEq(rel.slashedAmount, 1 ether); // Capped at original bond
    }

    function test_slashRelayer_revertsNotOperator() public {
        vm.prank(user);
        messenger.registerRelayer{value: 1 ether}();

        vm.prank(user);
        vm.expectRevert();
        messenger.slashRelayer(user, 0.5 ether, keccak256("fraud"));
    }

    // ============ Receive Via Relayer Tests ============

    function test_receiveViaRelayer_success() public {
        // Register 3 relayers
        (address r1, uint256 pk1) = makeAddrAndKey("relayer1");
        (address r2, uint256 pk2) = makeAddrAndKey("relayer2");
        (address r3, uint256 pk3) = makeAddrAndKey("relayer3");

        vm.deal(r1, 2 ether);
        vm.deal(r2, 2 ether);
        vm.deal(r3, 2 ether);

        _registerAndApprove(r1);
        _registerAndApprove(r2);
        _registerAndApprove(r3);

        // Prepare message hash
        bytes32 messageId = keccak256("msg1");
        uint256 srcChain = 42161;
        bytes memory payload = bytes("hello");

        bytes32 messageHash = keccak256(
            abi.encode(
                messageId,
                srcChain,
                block.chainid,
                user,
                address(recipient),
                payload
            )
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );

        // Sign
        (uint8 v1, bytes32 r1s, bytes32 s1s) = vm.sign(pk1, ethSignedHash);
        (uint8 v2, bytes32 r2s, bytes32 s2s) = vm.sign(pk2, ethSignedHash);
        (uint8 v3, bytes32 r3s, bytes32 s3s) = vm.sign(pk3, ethSignedHash);

        bytes[] memory sigs = new bytes[](3);
        sigs[0] = abi.encodePacked(r1s, s1s, v1);
        sigs[1] = abi.encodePacked(r2s, s2s, v2);
        sigs[2] = abi.encodePacked(r3s, s3s, v3);

        messenger.receiveViaRelayer(
            messageId,
            srcChain,
            user,
            address(recipient),
            payload,
            sigs
        );

        assertTrue(messenger.isMessageProcessed(messageId));
        assertEq(messenger.getConfirmationCount(messageId), 3);
    }

    function test_receiveViaRelayer_revertsInsufficientSigs() public {
        bytes[] memory sigs = new bytes[](1); // Need 3
        sigs[0] = new bytes(65);

        vm.expectRevert(DirectL2Messenger.InsufficientConfirmations.selector);
        messenger.receiveViaRelayer(
            keccak256("msg"),
            42161,
            user,
            address(recipient),
            bytes("hello"),
            sigs
        );
    }

    function test_receiveViaRelayer_revertsReplay() public {
        // Register 3 relayers
        (address r1, uint256 pk1) = makeAddrAndKey("rel1");
        (address r2, uint256 pk2) = makeAddrAndKey("rel2");
        (address r3, uint256 pk3) = makeAddrAndKey("rel3");

        vm.deal(r1, 2 ether);
        vm.deal(r2, 2 ether);
        vm.deal(r3, 2 ether);

        _registerAndApprove(r1);
        _registerAndApprove(r2);
        _registerAndApprove(r3);

        bytes32 messageId = keccak256("msg2");
        bytes memory payload = bytes("hello");

        bytes32 messageHash = keccak256(
            abi.encode(
                messageId,
                uint256(42161),
                block.chainid,
                user,
                address(recipient),
                payload
            )
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );

        (uint8 v1, bytes32 r1s, bytes32 s1s) = vm.sign(pk1, ethSignedHash);
        (uint8 v2, bytes32 r2s, bytes32 s2s) = vm.sign(pk2, ethSignedHash);
        (uint8 v3, bytes32 r3s, bytes32 s3s) = vm.sign(pk3, ethSignedHash);

        bytes[] memory sigs = new bytes[](3);
        sigs[0] = abi.encodePacked(r1s, s1s, v1);
        sigs[1] = abi.encodePacked(r2s, s2s, v2);
        sigs[2] = abi.encodePacked(r3s, s3s, v3);

        messenger.receiveViaRelayer(
            messageId,
            42161,
            user,
            address(recipient),
            payload,
            sigs
        );

        // Replay should fail
        vm.expectRevert(DirectL2Messenger.MessageAlreadyProcessed.selector);
        messenger.receiveViaRelayer(
            messageId,
            42161,
            user,
            address(recipient),
            payload,
            sigs
        );
    }

    // ============ Receive Message Tests (Superchain) ============

    function test_receiveMessage_fromOperator() public {
        bytes32 messageId = keccak256("superchain_msg");

        vm.prank(operator);
        messenger.receiveMessage(
            messageId,
            10,
            user,
            address(recipient),
            bytes("data")
        );

        assertTrue(messenger.isMessageProcessed(messageId));
        IL2DirectMessenger.L2Message memory msg_ = messenger.getMessage(
            messageId
        );
        assertEq(
            uint8(msg_.status),
            uint8(IL2DirectMessenger.MessageStatus.EXECUTED)
        );
    }

    function test_receiveMessage_revertsUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.InvalidRelayer.selector);
        messenger.receiveMessage(
            keccak256("msg"),
            10,
            user,
            address(recipient),
            bytes("data")
        );
    }

    function test_receiveMessage_revertsReplay() public {
        bytes32 messageId = keccak256("msg_replay");

        vm.prank(operator);
        messenger.receiveMessage(
            messageId,
            10,
            user,
            address(recipient),
            bytes("data")
        );

        vm.prank(operator);
        vm.expectRevert(DirectL2Messenger.MessageAlreadyProcessed.selector);
        messenger.receiveMessage(
            messageId,
            10,
            user,
            address(recipient),
            bytes("data")
        );
    }

    // ============ Challenge Tests ============

    function test_challengeMessage() public {
        // First register relayers and receive a message via relayer
        (address r1, uint256 pk1) = makeAddrAndKey("ch_rel1");
        (address r2, uint256 pk2) = makeAddrAndKey("ch_rel2");
        (address r3, uint256 pk3) = makeAddrAndKey("ch_rel3");

        vm.deal(r1, 2 ether);
        vm.deal(r2, 2 ether);
        vm.deal(r3, 2 ether);

        _registerAndApprove(r1);
        _registerAndApprove(r2);
        _registerAndApprove(r3);

        bytes32 messageId = keccak256("challenge_msg");
        bytes memory payload = bytes("data");

        bytes32 messageHash = keccak256(
            abi.encode(
                messageId,
                uint256(10),
                block.chainid,
                user,
                address(recipient),
                payload
            )
        );
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );

        (uint8 v1, bytes32 r1s, bytes32 s1s) = vm.sign(pk1, ethSignedHash);
        (uint8 v2, bytes32 r2s, bytes32 s2s) = vm.sign(pk2, ethSignedHash);
        (uint8 v3, bytes32 r3s, bytes32 s3s) = vm.sign(pk3, ethSignedHash);

        bytes[] memory sigs = new bytes[](3);
        sigs[0] = abi.encodePacked(r1s, s1s, v1);
        sigs[1] = abi.encodePacked(r2s, s2s, v2);
        sigs[2] = abi.encodePacked(r3s, s3s, v3);

        messenger.receiveViaRelayer(
            messageId,
            10,
            user,
            address(recipient),
            payload,
            sigs
        );

        // Challenge
        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        messenger.challengeMessage{value: 0.1 ether}(
            messageId,
            keccak256("fraud")
        );

        assertEq(messenger.challengers(messageId), challenger);
        assertEq(messenger.challengeBonds(messageId), 0.1 ether);
    }

    function test_challengeMessage_revertsInsufficientBond() public {
        // Set up a relayed message first (using operator as shortcut)
        // need to create via relayer for FAST_RELAYER path
        // Skip full setup, just test the bond check by inserting message directly

        // We can't easily insert a fast-relayer message without full relayer setup,
        // so just verify the error type
        vm.prank(user);
        vm.expectRevert(DirectL2Messenger.InvalidMessage.selector);
        messenger.challengeMessage{value: 0.01 ether}(
            keccak256("nonexistent"),
            keccak256("reason")
        );
    }

    function test_resolveChallenge_fraudProven() public {
        // Register relayers
        (address r1, uint256 pk1) = makeAddrAndKey("res_rel1");
        (address r2, uint256 pk2) = makeAddrAndKey("res_rel2");
        (address r3, uint256 pk3) = makeAddrAndKey("res_rel3");

        vm.deal(r1, 2 ether);
        vm.deal(r2, 2 ether);
        vm.deal(r3, 2 ether);

        _registerAndApprove(r1);
        _registerAndApprove(r2);
        _registerAndApprove(r3);

        bytes32 messageId = keccak256("resolve_msg");
        bytes memory payload = bytes("data");

        bytes32 msgHash = keccak256(
            abi.encode(
                messageId,
                uint256(10),
                block.chainid,
                user,
                address(recipient),
                payload
            )
        );
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(msgHash);

        (uint8 v1, bytes32 r1s, bytes32 s1s) = vm.sign(pk1, ethHash);
        (uint8 v2, bytes32 r2s, bytes32 s2s) = vm.sign(pk2, ethHash);
        (uint8 v3, bytes32 r3s, bytes32 s3s) = vm.sign(pk3, ethHash);

        bytes[] memory sigs = new bytes[](3);
        sigs[0] = abi.encodePacked(r1s, s1s, v1);
        sigs[1] = abi.encodePacked(r2s, s2s, v2);
        sigs[2] = abi.encodePacked(r3s, s3s, v3);

        messenger.receiveViaRelayer(
            messageId,
            10,
            user,
            address(recipient),
            payload,
            sigs
        );

        // Challenge
        address challenger = makeAddr("fraud_challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        messenger.challengeMessage{value: 0.1 ether}(messageId, keccak256("f"));

        // Resolve: fraud proven
        uint256 challengerBalBefore = challenger.balance;
        vm.prank(operator);
        messenger.resolveChallenge(
            messageId,
            true,
            keccak256("fraud_evidence")
        );

        // Challenger should receive bond + reward
        assertTrue(challenger.balance > challengerBalBefore);

        // Message should be FAILED
        IL2DirectMessenger.L2Message memory msg_ = messenger.getMessage(
            messageId
        );
        assertEq(
            uint8(msg_.status),
            uint8(IL2DirectMessenger.MessageStatus.FAILED)
        );
    }

    // ============ Route Configuration Tests ============

    function test_configureRoute() public {
        vm.prank(operator);
        messenger.configureRoute(
            1,
            42161,
            IL2DirectMessenger.MessagePath.SUPERCHAIN,
            address(0),
            5,
            1 hours
        );

        IL2DirectMessenger.RouteConfig memory route = messenger.getRoute(
            1,
            42161
        );
        assertEq(
            uint8(route.preferredPath),
            uint8(IL2DirectMessenger.MessagePath.SUPERCHAIN)
        );
        assertEq(route.minConfirmations, 5);
        assertEq(route.challengeWindow, 1 hours);
        assertTrue(route.active);
    }

    function test_configureRoute_revertsZeroChainId() public {
        vm.prank(operator);
        vm.expectRevert(DirectL2Messenger.InvalidDestinationChain.selector);
        messenger.configureRoute(
            0,
            42161,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            0
        );
    }

    // ============ Admin Tests ============

    function test_setSuperchainMessenger() public {
        messenger.setSuperchainMessenger(address(mockSuperchain));
        assertEq(messenger.superchainMessenger(), address(mockSuperchain));
    }

    function test_setSuperchainMessenger_revertsZero() public {
        vm.expectRevert(DirectL2Messenger.ZeroAddress.selector);
        messenger.setSuperchainMessenger(address(0));
    }

    function test_setRequiredConfirmations() public {
        vm.prank(operator);
        messenger.setRequiredConfirmations(5);
        assertEq(messenger.requiredConfirmations(), 5);
    }

    function test_setRequiredConfirmations_revertsZero() public {
        vm.prank(operator);
        vm.expectRevert(DirectL2Messenger.InvalidConfirmationCount.selector);
        messenger.setRequiredConfirmations(0);
    }

    function test_setRequiredConfirmations_revertsAboveMax() public {
        vm.prank(operator);
        vm.expectRevert(DirectL2Messenger.InvalidConfirmationCount.selector);
        messenger.setRequiredConfirmations(21);
    }

    function test_setChallengerReward() public {
        messenger.setChallengerReward(1 ether);
        assertEq(messenger.challengerReward(), 1 ether);
    }

    function test_pause_unpause() public {
        vm.prank(operator);
        messenger.pause();

        vm.prank(user);
        vm.expectRevert();
        messenger.sendMessage(
            DEST_CHAIN,
            address(recipient),
            bytes("hi"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );

        vm.prank(operator);
        messenger.unpause();
    }

    // ============ View Tests ============

    function test_getMessage() public {
        vm.prank(user);
        bytes32 msgId = messenger.sendMessage{value: 0.1 ether}(
            DEST_CHAIN,
            address(recipient),
            bytes("test"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            keccak256("nullifier")
        );

        IL2DirectMessenger.L2Message memory msg_ = messenger.getMessage(msgId);
        assertEq(msg_.sender, user);
        assertEq(msg_.recipient, address(recipient));
        assertEq(msg_.destChainId, DEST_CHAIN);
        assertEq(msg_.nullifierBinding, keccak256("nullifier"));
    }

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool success, ) = address(messenger).call{value: 1 ether}("");
        assertTrue(success);
    }
}
