// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ScrollBridgeAdapter.sol";

/// @dev Mock Scroll Messenger that succeeds
contract MockScrollMessenger {
    bool public messageSent;
    uint256 public lastValue;
    bytes public lastCallData;

    function sendMessage(
        address,
        uint256 value,
        bytes calldata,
        uint256
    ) external payable {
        messageSent = true;
        lastValue = value;
    }

    receive() external payable {}

    /// Accept any call for fallback routing
    fallback() external payable {
        messageSent = true;
        lastCallData = msg.data;
    }
}

/// @dev Mock Scroll Messenger that always fails
contract FailingScrollMessenger {
    fallback() external payable {
        revert("Scroll messenger call failed");
    }
}

/**
 * @title ScrollBridgeAdapterExtendedTest
 * @notice Comprehensive integration tests for ScrollBridgeAdapter covering:
 *         configureScrollBridge, sendMessage success path, verifyMessage
 *         with real state, zero-address reverts, pause-when-sending,
 *         emergencyWithdrawETH edge cases, and event emissions.
 */
contract ScrollBridgeAdapterExtendedTest is Test {
    ScrollBridgeAdapter public adapter;
    MockScrollMessenger public mockMessenger;

    address admin = address(0xAD1);
    address operator;
    address user = address(0xBEEF);

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        mockMessenger = new MockScrollMessenger();
        operator = admin; // admin gets OPERATOR_ROLE in constructor

        adapter = new ScrollBridgeAdapter(
            address(mockMessenger),
            address(0x6A7E),
            address(0x10CC),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(PAUSER_ROLE, admin);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                  configureScrollBridge — FULL COVERAGE
    //////////////////////////////////////////////////////////////*/

    function test_configureScrollBridge_success() public {
        address newMessenger = makeAddr("newMessenger");
        address newGateway = makeAddr("newGateway");
        address newRollup = makeAddr("newRollup");

        vm.prank(admin);
        adapter.configureScrollBridge(newMessenger, newGateway, newRollup);

        assertEq(adapter.scrollMessenger(), newMessenger);
        assertEq(adapter.gatewayRouter(), newGateway);
        assertEq(adapter.rollupContract(), newRollup);
    }

    function test_configureScrollBridge_emitsBridgeConfigured() public {
        address newMessenger = makeAddr("m");
        address newGateway = makeAddr("g");
        address newRollup = makeAddr("r");

        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit ScrollBridgeAdapter.BridgeConfigured(
            newMessenger,
            newGateway,
            newRollup
        );
        adapter.configureScrollBridge(newMessenger, newGateway, newRollup);
    }

    function test_configureScrollBridge_revert_zeroScrollMessenger() public {
        vm.prank(admin);
        vm.expectRevert("Invalid scroll messenger");
        adapter.configureScrollBridge(address(0), makeAddr("g"), makeAddr("r"));
    }

    function test_configureScrollBridge_revert_zeroGatewayRouter() public {
        vm.prank(admin);
        vm.expectRevert("Invalid gateway router");
        adapter.configureScrollBridge(makeAddr("m"), address(0), makeAddr("r"));
    }

    function test_configureScrollBridge_revert_zeroRollupContract() public {
        vm.prank(admin);
        vm.expectRevert("Invalid rollup contract");
        adapter.configureScrollBridge(makeAddr("m"), makeAddr("g"), address(0));
    }

    function test_configureScrollBridge_revert_nonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.configureScrollBridge(
            makeAddr("m"),
            makeAddr("g"),
            makeAddr("r")
        );
    }

    /*//////////////////////////////////////////////////////////////
                 sendMessage — SUCCESS PATH & EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        address target = makeAddr("target");
        bytes memory data = hex"deadbeef";

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            target,
            data,
            500_000
        );

        assertTrue(msgHash != bytes32(0), "Message hash should be non-zero");
        assertTrue(mockMessenger.messageSent(), "Messenger should record call");
        assertEq(adapter.messageNonce(), 1, "Nonce should increment");
    }

    function test_sendMessage_emits_MessageSent() public {
        address target = makeAddr("target");

        vm.deal(admin, 1 ether);
        vm.prank(admin);

        vm.expectEmit(false, true, false, false);
        emit ScrollBridgeAdapter.MessageSent(bytes32(0), target, 0);

        adapter.sendMessage{value: 0.01 ether}(target, hex"aa", 200_000);
    }

    function test_sendMessage_usesDefaultGasLimit() public {
        address target = makeAddr("target");

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        adapter.sendMessage{value: 0.01 ether}(target, hex"aa", 0);
        // gasLimit=0 → uses DEFAULT_L2_GAS_LIMIT (1_000_000)
        // No revert = success
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_setsStatusToSent() public {
        address target = makeAddr("target");

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            target,
            hex"aa",
            200_000
        );

        uint8 status = uint8(adapter.messageStatus(msgHash));
        assertEq(status, uint8(ScrollBridgeAdapter.MessageStatus.SENT));
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        vm.expectRevert("Invalid target");
        adapter.sendMessage{value: 0.01 ether}(address(0), hex"aa", 200_000);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(admin);
        adapter.pause();

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.sendMessage{value: 0.01 ether}(makeAddr("t"), hex"aa", 200_000);
    }

    function test_sendMessage_revert_failingMessenger() public {
        // Deploy adapter with failing messenger
        FailingScrollMessenger failingMessenger = new FailingScrollMessenger();
        ScrollBridgeAdapter failAdapter = new ScrollBridgeAdapter(
            address(failingMessenger),
            address(0x6A7E),
            address(0x10CC),
            admin
        );

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        vm.expectRevert("Scroll messenger call failed");
        failAdapter.sendMessage{value: 0.01 ether}(
            makeAddr("t"),
            hex"aa",
            200_000
        );
    }

    function test_sendMessage_incrementsNonce_sequential() public {
        vm.deal(admin, 10 ether);

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(admin);
            adapter.sendMessage{value: 0.01 ether}(
                makeAddr("target"),
                abi.encodePacked(hex"aa", i),
                200_000
            );
        }

        assertEq(adapter.messageNonce(), 5, "Nonce should be 5 after 5 sends");
    }

    /*//////////////////////////////////////////////////////////////
                  verifyMessage — WITH STATUS TRANSITIONS
    //////////////////////////////////////////////////////////////*/

    function test_verifyMessage_sentMessage_valid() public {
        address target = makeAddr("target");
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            target,
            hex"aa",
            200_000
        );

        // Message is SENT, proof is non-empty → should verify
        assertTrue(adapter.verifyMessage(msgHash, hex"aabbccdd"));
    }

    function test_verifyMessage_pendingMessage_invalid() public {
        // Random hash has PENDING status and non-empty proof
        bytes32 randomHash = keccak256("random");
        assertFalse(
            adapter.verifyMessage(randomHash, hex"aabbccdd"),
            "PENDING message should not verify"
        );
    }

    function test_verifyMessage_emptyAndNonEmptyProof() public {
        // Even a SENT message should fail with empty proof
        address target = makeAddr("target");
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            target,
            hex"aa",
            200_000
        );

        assertFalse(
            adapter.verifyMessage(msgHash, hex""),
            "Empty proof should fail"
        );
        assertTrue(
            adapter.verifyMessage(msgHash, hex"deadbeef"),
            "Non-empty proof should succeed"
        );
    }

    /*//////////////////////////////////////////////////////////////
                  setSoulHubL2 & setProofRegistry — ZERO ADDRESS
    //////////////////////////////////////////////////////////////*/

    function test_setSoulHubL2_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setSoulHubL2(address(0));
    }

    function test_setSoulHubL2_emitsEvent() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit ScrollBridgeAdapter.SoulHubL2Set(hub);
        adapter.setSoulHubL2(hub);
    }

    function test_setProofRegistry_emitsEvent() public {
        address registry = makeAddr("registry");
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit ScrollBridgeAdapter.ProofRegistrySet(registry);
        adapter.setProofRegistry(registry);
    }

    function test_setProofRegistry_allowsZero() public {
        // setProofRegistry doesn't check for zero address in the contract
        vm.prank(admin);
        adapter.setProofRegistry(address(0));
        assertEq(adapter.proofRegistry(), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                  emergencyWithdrawETH — EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_emergencyWithdrawETH_insufficientBalance() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        vm.expectRevert("Insufficient balance");
        adapter.emergencyWithdrawETH(payable(admin), 2 ether);
    }

    function test_emergencyWithdrawETH_zeroRecipient() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        vm.expectRevert("Invalid recipient");
        adapter.emergencyWithdrawETH(payable(address(0)), 0.5 ether);
    }

    function test_emergencyWithdrawETH_fullBalance() public {
        vm.deal(address(adapter), 5 ether);
        uint256 balBefore = admin.balance;

        vm.prank(admin);
        adapter.emergencyWithdrawETH(payable(admin), 5 ether);

        assertEq(address(adapter).balance, 0, "Adapter should have 0 balance");
        assertEq(
            admin.balance,
            balBefore + 5 ether,
            "Admin should receive full amount"
        );
    }

    function test_emergencyWithdrawETH_zeroAmount() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        adapter.emergencyWithdrawETH(payable(admin), 0);
        // No revert = success (transfer of 0 is valid)
    }

    /*//////////////////////////////////////////////////////////////
                  CONSTRUCTOR — ADDITIONAL CASES
    //////////////////////////////////////////////////////////////*/

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new ScrollBridgeAdapter(
            address(mockMessenger),
            address(0x6A7E),
            address(0x10CC),
            address(0)
        );
    }

    function test_constructor_revert_zeroMessenger() public {
        vm.expectRevert("Invalid scroll messenger");
        new ScrollBridgeAdapter(
            address(0),
            address(0x6A7E),
            address(0x10CC),
            admin
        );
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_sendMessage_variableGasLimits(uint256 gasLimit) public {
        gasLimit = bound(gasLimit, 0, 30_000_000);

        vm.deal(admin, 1 ether);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            makeAddr("target"),
            hex"deadbeef",
            gasLimit
        );
        assertTrue(msgHash != bytes32(0));
    }

    function testFuzz_sendMessage_variableValues(uint256 value) public {
        value = bound(value, 0, 10 ether);

        vm.deal(admin, value + 1);
        vm.prank(admin);
        bytes32 msgHash = adapter.sendMessage{value: value}(
            makeAddr("target"),
            hex"aa",
            200_000
        );
        assertTrue(msgHash != bytes32(0));
    }
}
