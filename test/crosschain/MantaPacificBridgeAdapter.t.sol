// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/MantaPacificBridgeAdapter.sol";

/// @dev Mock CDK Bridge that records bridgeMessage calls
contract MockCDKBridge {
    uint32 public depositCount;

    function bridgeMessage(
        uint32 /* destinationNetwork */,
        address /* destinationAddress */,
        bool /* forceUpdateGlobalExitRoot */,
        bytes calldata /* metadata */
    ) external payable returns (uint256) {
        return uint256(++depositCount);
    }

    /// @dev Accept claimMessage calls
    fallback() external payable {}

    receive() external payable {}
}

/// @dev Mock Global Exit Root Manager
contract MockGlobalExitRootManager {
    function getLastGlobalExitRoot() external pure returns (bytes32) {
        return keccak256("global_exit_root");
    }
}

/// @dev Mock Manta Rollup
contract MockMantaRollup {
    function lastVerifiedBatch() external pure returns (uint256) {
        return 42;
    }
}

contract MantaPacificBridgeAdapterTest is Test {
    MantaPacificBridgeAdapter public adapter;
    MockCDKBridge public mockBridge;
    MockGlobalExitRootManager public mockGER;
    MockMantaRollup public mockRollup;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");
    uint32 networkId = 1;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        mockBridge = new MockCDKBridge();
        mockGER = new MockGlobalExitRootManager();
        mockRollup = new MockMantaRollup();

        adapter = new MantaPacificBridgeAdapter(
            address(mockBridge),
            address(mockGER),
            address(mockRollup),
            networkId,
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        vm.stopPrank();
    }

    // ── Constructor ──

    function test_constructor_setsStorage() public view {
        assertEq(adapter.cdkBridge(), address(mockBridge));
        assertEq(adapter.globalExitRootManager(), address(mockGER));
        assertEq(adapter.mantaRollup(), address(mockRollup));
        assertEq(adapter.networkId(), networkId);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new MantaPacificBridgeAdapter(
            address(mockBridge),
            address(mockGER),
            address(mockRollup),
            networkId,
            address(0)
        );
    }

    function test_constructor_revert_zeroBridge() public {
        vm.expectRevert("Invalid CDK bridge");
        new MantaPacificBridgeAdapter(
            address(0),
            address(mockGER),
            address(mockRollup),
            networkId,
            admin
        );
    }

    function test_constructor_revert_zeroGER() public {
        vm.expectRevert("Invalid exit root manager");
        new MantaPacificBridgeAdapter(
            address(mockBridge),
            address(0),
            address(mockRollup),
            networkId,
            admin
        );
    }

    function test_constructor_revert_zeroRollup() public {
        vm.expectRevert("Invalid rollup");
        new MantaPacificBridgeAdapter(
            address(mockBridge),
            address(mockGER),
            address(0),
            networkId,
            admin
        );
    }

    // ── Constants ──

    function test_constants() public view {
        assertEq(adapter.MANTA_PACIFIC_CHAIN_ID(), 169);
        assertEq(adapter.MANTA_SEPOLIA_CHAIN_ID(), 3441006);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.NETWORK_ID_MAINNET(), 0);
        assertEq(adapter.NETWORK_ID_MANTA(), 1);
    }

    // ── Bridge Interface ──

    function test_chainId() public view {
        assertEq(adapter.chainId(), 169);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Manta Pacific");
    }

    function test_isConfigured_false_noHub() public view {
        assertFalse(adapter.isConfigured());
    }

    function test_isConfigured_true() public {
        vm.prank(admin);
        adapter.setZaseonHubL2(makeAddr("hub"));
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── Configuration ──

    function test_configureMantaBridge() public {
        address newBridge = makeAddr("newBridge");
        address newGER = makeAddr("newGER");
        address newRollup = makeAddr("newRollup");

        vm.prank(operator);
        adapter.configureMantaBridge(newBridge, newGER, newRollup);

        assertEq(adapter.cdkBridge(), newBridge);
        assertEq(adapter.globalExitRootManager(), newGER);
        assertEq(adapter.mantaRollup(), newRollup);
    }

    function test_configureMantaBridge_revert_zeroBridge() public {
        vm.prank(operator);
        vm.expectRevert("Invalid CDK bridge");
        adapter.configureMantaBridge(
            address(0),
            address(mockGER),
            address(mockRollup)
        );
    }

    function test_setZaseonHubL2() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        adapter.setZaseonHubL2(hub);
        assertEq(adapter.zaseonHubL2(), hub);
    }

    function test_setZaseonHubL2_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setZaseonHubL2(address(0));
    }

    function test_setProofRegistry() public {
        address reg = makeAddr("registry");
        vm.prank(admin);
        adapter.setProofRegistry(reg);
        assertEq(adapter.proofRegistry(), reg);
    }

    // ── sendMessage ──

    function test_sendMessage_success() public {
        address target = makeAddr("target");

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            target,
            hex"deadbeef",
            false
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_forceUpdate() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage(makeAddr("t"), hex"aa", true);
        assertTrue(hash != bytes32(0));
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage(address(0), hex"aa", false);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", false);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", false);
    }

    // ── getLastVerifiedBatch ──

    function test_getLastVerifiedBatch() public view {
        assertEq(adapter.getLastVerifiedBatch(), 42);
    }

    // ── verifyMessage ──

    function test_verifyMessage_emptyProof_returnsFalse() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), hex""));
    }

    // ── Pause / Unpause ──

    function test_pause() public {
        vm.prank(pauser);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    // ── emergencyWithdrawETH ──

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 3 ether);
        assertEq(recipient.balance, 3 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    // ── Receive ETH ──

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // ── Role constants ──

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), OPERATOR_ROLE);
        assertEq(adapter.GUARDIAN_ROLE(), GUARDIAN_ROLE);
        assertEq(adapter.RELAYER_ROLE(), RELAYER_ROLE);
        assertEq(adapter.PAUSER_ROLE(), PAUSER_ROLE);
    }
}
