// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/MantleBridgeAdapter.sol";

/// @dev Mock CrossDomainMessenger that accepts sendMessage calls
contract MockCrossDomainMessengerMantle {
    uint256 public lastGasLimit;
    address public lastTarget;

    function sendMessage(
        address _target,
        bytes memory,
        uint32 _minGasLimit
    ) external payable {
        lastTarget = _target;
        lastGasLimit = _minGasLimit;
    }
}

/// @dev Mock L2OutputOracle
contract MockOutputOracleMantle {
    function getL2Output(uint256) external pure returns (bytes32) {
        return keccak256("output_root");
    }
}

/// @dev Mock portal
contract MockMantlePortal {
    fallback() external payable {}

    receive() external payable {}
}

contract MantleBridgeAdapterTest is Test {
    MantleBridgeAdapter public adapter;
    MockCrossDomainMessengerMantle public mockMessenger;
    MockOutputOracleMantle public mockOracle;
    MockMantlePortal public mockPortal;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        mockMessenger = new MockCrossDomainMessengerMantle();
        mockOracle = new MockOutputOracleMantle();
        mockPortal = new MockMantlePortal();

        adapter = new MantleBridgeAdapter(
            address(mockMessenger),
            address(mockOracle),
            address(mockPortal),
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
        assertEq(adapter.crossDomainMessenger(), address(mockMessenger));
        assertEq(adapter.outputOracle(), address(mockOracle));
        assertEq(adapter.mantlePortal(), address(mockPortal));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new MantleBridgeAdapter(
            address(mockMessenger),
            address(mockOracle),
            address(mockPortal),
            address(0)
        );
    }

    function test_constructor_revert_zeroMessenger() public {
        vm.expectRevert("Invalid cross domain messenger");
        new MantleBridgeAdapter(
            address(0),
            address(mockOracle),
            address(mockPortal),
            admin
        );
    }

    function test_constructor_revert_zeroOracle() public {
        vm.expectRevert("Invalid output oracle");
        new MantleBridgeAdapter(
            address(mockMessenger),
            address(0),
            address(mockPortal),
            admin
        );
    }

    function test_constructor_revert_zeroPortal() public {
        vm.expectRevert("Invalid portal");
        new MantleBridgeAdapter(
            address(mockMessenger),
            address(mockOracle),
            address(0),
            admin
        );
    }

    // ── Constants ──

    function test_constants() public view {
        assertEq(adapter.MANTLE_CHAIN_ID(), 5000);
        assertEq(adapter.MANTLE_SEPOLIA_CHAIN_ID(), 5003);
        assertEq(adapter.FINALITY_BLOCKS(), 50400);
        assertEq(adapter.DEFAULT_L2_GAS_LIMIT(), 1_000_000);
    }

    // ── Bridge Interface ──

    function test_chainId() public view {
        assertEq(adapter.chainId(), 5000);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Mantle");
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
        assertEq(adapter.getFinalityBlocks(), 50400);
    }

    // ── Configuration ──

    function test_configureMantleBridge() public {
        address newMsg = makeAddr("newMsg");
        address newOracle = makeAddr("newOracle");
        address newPortal = makeAddr("newPortal");

        vm.prank(operator);
        adapter.configureMantleBridge(newMsg, newOracle, newPortal);

        assertEq(adapter.crossDomainMessenger(), newMsg);
        assertEq(adapter.outputOracle(), newOracle);
        assertEq(adapter.mantlePortal(), newPortal);
    }

    function test_configureMantleBridge_revert_zeroMessenger() public {
        vm.prank(operator);
        vm.expectRevert("Invalid cross domain messenger");
        adapter.configureMantleBridge(
            address(0),
            address(mockOracle),
            address(mockPortal)
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
        bytes memory data = hex"deadbeef";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(target, data, 0);

        assertTrue(hash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_customGasLimit() public {
        address target = makeAddr("target");

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage(target, hex"aa", 500_000);
        assertTrue(hash != bytes32(0));
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage(address(0), hex"aa", 0);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", 0);
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

    // ── IBridgeAdapter Compliance ──

    function test_bridgeMessage_revert_notOperator() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        adapter.bridgeMessage(
            makeAddr("target"),
            hex"dead",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), hex"dead");
        assertEq(fee, 0);
    }

    function test_isMessageVerified_unknownId() public {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(999))));
    }
}
