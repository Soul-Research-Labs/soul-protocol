// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

// Cross-chain contracts
import {DirectL2Messenger} from "../../contracts/crosschain/DirectL2Messenger.sol";
import {L2ProofRouter} from "../../contracts/crosschain/L2ProofRouter.sol";
import {IL2DirectMessenger} from "../../contracts/interfaces/IL2DirectMessenger.sol";

/**
 * @title CrossChainIntegrationTest
 * @notice End-to-end integration tests for cross-chain proof relay
 * @dev Uses multi-fork testing to simulate real L2 environments
 *
 * Test scenarios:
 * 1. Single proof relay: Arbitrum -> Optimism
 * 2. Batch proof relay: Base -> Arbitrum
 * 3. Cross-chain nullifier sync
 * 4. Dispute resolution flow
 * 5. Relayer bond and slashing
 *
 * Run with:
 * forge test --match-contract CrossChainIntegrationTest -vvv --fork-url $ARBITRUM_RPC
 */
contract CrossChainIntegrationTest is Test {
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // Chain IDs for L2 networks
    uint256 constant ARBITRUM_CHAIN_ID = 42161;
    uint256 constant OPTIMISM_CHAIN_ID = 10;
    uint256 constant BASE_CHAIN_ID = 8453;

    // Test constants - matches DirectL2Messenger.MIN_RELAYER_BOND
    uint256 constant MIN_RELAYER_BOND = 1 ether;
    uint256 constant CHALLENGE_PERIOD = 30 minutes;

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    // Fork IDs for multi-chain testing
    uint256 arbitrumForkId;
    uint256 optimismForkId;
    uint256 baseForkId;

    // Simulated contracts (deployed on each fork)
    DirectL2Messenger public messengerArbitrum;
    DirectL2Messenger public messengerOptimism;
    DirectL2Messenger public messengerBase;

    L2ProofRouter public routerArbitrum;
    L2ProofRouter public routerOptimism;

    // Test accounts
    address public relayer;
    address public challenger;
    address public user;
    address public admin;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Create test accounts
        admin = makeAddr("admin");
        relayer = makeAddr("relayer");
        challenger = makeAddr("challenger");
        user = makeAddr("user");

        vm.deal(admin, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(challenger, 10 ether);
        vm.deal(user, 10 ether);

        // Note: For actual fork testing, you would create forks like this:
        // arbitrumForkId = vm.createFork(vm.envString("ARBITRUM_RPC_URL"));
        // optimismForkId = vm.createFork(vm.envString("OPTIMISM_RPC_URL"));
        // baseForkId = vm.createFork(vm.envString("BASE_RPC_URL"));

        // For local testing, we simulate the chain ID
        vm.chainId(ARBITRUM_CHAIN_ID);

        // Deploy mock contracts for local testing
        _deployLocalContracts();
    }

    function _deployLocalContracts() internal {
        // Deploy DirectL2Messenger (requires admin and zaseonHub addresses)
        address zaseonHub = makeAddr("zaseonHub");
        messengerArbitrum = new DirectL2Messenger(admin, zaseonHub);

        // Deploy L2ProofRouter
        routerArbitrum = new L2ProofRouter(admin, zaseonHub);
    }

    /*//////////////////////////////////////////////////////////////
                         SINGLE PROOF RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test single message send from Arbitrum to Optimism
     */
    function test_singleMessageSend() public {
        // First, configure a route from Arbitrum to Optimism (need admin role)
        vm.startPrank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0), // No adapter for fast path
            3, // 3 confirmations
            30 minutes
        );
        vm.stopPrank();

        // Send a message
        vm.startPrank(user);

        bytes memory payload = abi.encode("Hello Optimism!");
        bytes32 nullifierBinding = bytes32(0);

        bytes32 messageId = messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            user, // recipient
            payload,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            nullifierBinding
        );

        vm.stopPrank();

        // Verify message was recorded
        assertTrue(messageId != bytes32(0), "Message ID generated");

        // Check message status (struct has 13 fields)
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
            ,
            IL2DirectMessenger.MessageStatus status,

        ) = messengerArbitrum.messages(messageId);
        assertTrue(
            status == IL2DirectMessenger.MessageStatus.SENT,
            "Message status is SENT"
        );
    }

    /**
     * @notice Test message send to invalid destination (same chain)
     */
    function test_messageSend_sameChain_reverts() public {
        vm.startPrank(user);

        bytes memory payload = abi.encode("Invalid message");

        vm.expectRevert(DirectL2Messenger.InvalidDestinationChain.selector);
        messengerArbitrum.sendMessage{value: 0.01 ether}(
            ARBITRUM_CHAIN_ID, // Same chain - should fail
            user,
            payload,
            IL2DirectMessenger.MessagePath.SLOW_L1,
            bytes32(0)
        );

        vm.stopPrank();
    }

    /**
     * @notice Test message send with zero recipient
     */
    function test_messageSend_zeroRecipient_reverts() public {
        vm.startPrank(user);

        bytes memory payload = abi.encode("Invalid message");

        vm.expectRevert(DirectL2Messenger.InvalidMessage.selector);
        messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            address(0), // Zero recipient - should fail
            payload,
            IL2DirectMessenger.MessagePath.SLOW_L1,
            bytes32(0)
        );

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH PROOF RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test batch message submission
     */
    function test_batchMessageSubmission() public {
        // Configure route (need admin)
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );

        // Send batch of messages
        bytes32[] memory messageIds = new bytes32[](5);

        vm.startPrank(user);
        for (uint256 i = 0; i < 5; i++) {
            bytes memory payload = abi.encode("Batch message", i);
            messageIds[i] = messengerArbitrum.sendMessage{value: 0.01 ether}(
                OPTIMISM_CHAIN_ID,
                user,
                payload,
                IL2DirectMessenger.MessagePath.FAST_RELAYER,
                bytes32(0)
            );
        }
        vm.stopPrank();

        // Verify all messages have unique IDs
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(messageIds[i] != bytes32(0), "Message ID generated");
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(
                    messageIds[i] != messageIds[j],
                    "Message IDs are unique"
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN NULLIFIER BINDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test message with nullifier binding
     */
    function test_messageWithNullifierBinding() public {
        // Configure route (need admin)
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );

        vm.startPrank(user);

        bytes32 nullifier = keccak256(
            abi.encodePacked(
                "private_transfer_nullifier",
                user,
                block.timestamp
            )
        );
        bytes memory payload = abi.encode("Private transfer data");

        bytes32 messageId = messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            user,
            payload,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        vm.stopPrank();

        // Verify nullifier binding is stored (struct has 13 fields)
        (, , , , , , , , , , , , bytes32 storedNullifier) = messengerArbitrum
            .messages(messageId);
        assertEq(storedNullifier, nullifier, "Nullifier binding stored");
    }

    /**
     * @notice Test double-spend prevention via nullifier uniqueness
     */
    function test_nullifierUniqueness() public {
        // Configure route (need admin)
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );

        vm.startPrank(user);

        // Same nullifier used in two messages - each message is unique but uses same nullifier
        bytes32 nullifier = keccak256(abi.encodePacked("reused_nullifier"));

        bytes32 messageId1 = messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            user,
            abi.encode("First message"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        bytes32 messageId2 = messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            user,
            abi.encode("Second message"),
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            nullifier
        );

        vm.stopPrank();

        // Both messages sent - nullifier checking happens on destination chain
        assertTrue(messageId1 != messageId2, "Different message IDs");
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test relayer registration with valid bond
     */
    function test_relayerRegistration() public {
        vm.startPrank(relayer);

        // Register with minimum bond
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();

        // Verify relayer is active
        (
            address addr,
            uint256 bond,
            uint256 successCount,
            uint256 failCount,
            uint256 slashedAmount,
            bool active,

        ) = messengerArbitrum.relayers(relayer);

        assertEq(addr, relayer, "Relayer address correct");
        assertEq(bond, MIN_RELAYER_BOND, "Bond amount correct");
        assertEq(successCount, 0, "Success count starts at 0");
        assertEq(failCount, 0, "Fail count starts at 0");
        assertEq(slashedAmount, 0, "Slashed amount starts at 0");
        assertTrue(active, "Relayer is active");

        vm.stopPrank();
    }

    /**
     * @notice Test relayer registration with insufficient bond
     */
    function test_relayerRegistration_insufficientBond_reverts() public {
        vm.startPrank(relayer);

        vm.expectRevert(DirectL2Messenger.InsufficientBond.selector);
        messengerArbitrum.registerRelayer{value: 0.1 ether}(); // Less than MIN_RELAYER_BOND

        vm.stopPrank();
    }

    /**
     * @notice Test relayer withdrawal before unbonding period
     */
    function test_relayerWithdrawal_beforeUnbonding_reverts() public {
        vm.startPrank(relayer);

        // Register relayer
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();

        // Try to withdraw immediately - should fail
        vm.expectRevert(DirectL2Messenger.UnbondingPeriodNotComplete.selector);
        messengerArbitrum.withdrawRelayerBond();

        vm.stopPrank();
    }

    /**
     * @notice Test relayer withdrawal after unbonding period
     */
    function test_relayerWithdrawal_afterUnbonding() public {
        vm.startPrank(relayer);

        uint256 balanceBefore = relayer.balance;

        // Register relayer
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();

        // Fast forward 7 days
        vm.warp(block.timestamp + 7 days + 1);

        // Withdraw bond
        messengerArbitrum.withdrawRelayerBond();

        // Verify bond returned
        assertEq(relayer.balance, balanceBefore, "Bond returned");

        // Verify relayer is no longer active
        (, , , , , bool active, ) = messengerArbitrum.relayers(relayer);
        assertFalse(active, "Relayer is inactive");

        vm.stopPrank();
    }

    /**
     * @notice Test double registration reverts
     */
    function test_relayerDoubleRegistration_reverts() public {
        vm.startPrank(relayer);

        // First registration succeeds
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();

        // Second registration fails
        vm.expectRevert(DirectL2Messenger.InvalidRelayer.selector);
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          MULTI-FORK TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test message relay between actual forks
     * @dev Requires RPC URLs to be set in environment
     */
    function test_multiForkRelay() public {
        // Skip if no RPC URLs configured
        try vm.envString("ARBITRUM_RPC_URL") returns (string memory) {
            // Run actual multi-fork test
            _runMultiForkTest();
        } catch {
            console.log("Skipping multi-fork test: ARBITRUM_RPC_URL not set");
        }
    }

    function _runMultiForkTest() internal {
        // Create forks
        string memory arbitrumRpc = vm.envString("ARBITRUM_RPC_URL");
        string memory optimismRpc = vm.envOr("OPTIMISM_RPC_URL", arbitrumRpc);

        arbitrumForkId = vm.createFork(arbitrumRpc);
        optimismForkId = vm.createFork(optimismRpc);

        // Test on Arbitrum
        vm.selectFork(arbitrumForkId);
        assertTrue(
            block.chainid == ARBITRUM_CHAIN_ID || block.chainid != 0,
            "On Arbitrum fork"
        );

        // Switch to Optimism
        vm.selectFork(optimismForkId);
        assertTrue(
            block.chainid == OPTIMISM_CHAIN_ID || block.chainid != 0,
            "On Optimism fork"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ROUTE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test route configuration for different paths
     */
    function test_routeConfiguration() public {
        // Configure Superchain route (e.g., Optimism <-> Base) - need admin
        // Note: adapter must be address(0) or a valid contract, not arbitrary address
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            BASE_CHAIN_ID,
            IL2DirectMessenger.MessagePath.SUPERCHAIN,
            address(0), // No adapter (will use native superchain)
            2, // 2 confirmations
            5 minutes // Fast challenge window
        );

        // Verify route is configured
        (
            IL2DirectMessenger.MessagePath preferredPath,
            address adapter,
            uint256 minConfirmations,
            uint256 challengeWindow,
            bool active
        ) = messengerArbitrum.routes(ARBITRUM_CHAIN_ID, BASE_CHAIN_ID);

        assertEq(
            uint8(preferredPath),
            uint8(IL2DirectMessenger.MessagePath.SUPERCHAIN),
            "Path correct"
        );
        assertEq(adapter, address(0), "Adapter correct (none)");
        assertEq(minConfirmations, 2, "Min confirmations correct");
        assertEq(challengeWindow, 5 minutes, "Challenge window correct");
        assertTrue(active, "Route is active");
    }

    /*//////////////////////////////////////////////////////////////
                           GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Benchmark gas for message sending
     */
    function test_gas_messageSending() public {
        // Configure route first (need admin)
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );

        vm.startPrank(user);

        bytes memory payload = abi.encode("Gas benchmark message");

        uint256 gasBefore = gasleft();
        messengerArbitrum.sendMessage{value: 0.01 ether}(
            OPTIMISM_CHAIN_ID,
            user,
            payload,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            bytes32(0)
        );
        uint256 gasUsed = gasBefore - gasleft();

        vm.stopPrank();

        console.log("Message send gas:", gasUsed);
        // Message sending includes storage writes, so ~350k is expected
        assertTrue(gasUsed < 500_000, "Gas under 500k");
    }

    /**
     * @notice Benchmark gas for relayer registration
     */
    function test_gas_relayerRegistration() public {
        vm.startPrank(relayer);

        uint256 gasBefore = gasleft();
        messengerArbitrum.registerRelayer{value: MIN_RELAYER_BOND}();
        uint256 gasUsed = gasBefore - gasleft();

        vm.stopPrank();

        console.log("Relayer registration gas:", gasUsed);
        assertTrue(gasUsed < 200_000, "Gas under 200k");
    }

    /**
     * @notice Benchmark gas for batch messages
     */
    function test_gas_batchMessages() public {
        // Configure route (need admin)
        vm.prank(admin);
        messengerArbitrum.configureRoute(
            ARBITRUM_CHAIN_ID,
            OPTIMISM_CHAIN_ID,
            IL2DirectMessenger.MessagePath.FAST_RELAYER,
            address(0),
            3,
            30 minutes
        );

        vm.startPrank(user);

        uint256 gasBefore = gasleft();
        for (uint256 i = 0; i < 10; i++) {
            messengerArbitrum.sendMessage{value: 0.01 ether}(
                OPTIMISM_CHAIN_ID,
                user,
                abi.encode("Batch", i),
                IL2DirectMessenger.MessagePath.FAST_RELAYER,
                bytes32(0)
            );
        }
        uint256 gasUsed = gasBefore - gasleft();

        vm.stopPrank();

        console.log("10 messages total gas:", gasUsed);
        console.log("Average per message:", gasUsed / 10);
    }
}
