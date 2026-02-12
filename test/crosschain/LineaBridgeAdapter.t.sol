// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/experimental/adapters/LineaBridgeAdapter.sol";

/// @dev Mock Linea MessageService that accepts calls
contract MockLineaMessageService {
    uint256 public lastFee;

    function sendMessage(
        address,
        uint256 fee,
        bytes calldata
    ) external payable {
        lastFee = fee;
    }

    function claimMessage(
        uint256,
        bytes32[] calldata
    ) external {
        // success
    }
}

/// @dev Mock Linea Rollup
contract MockLineaRollup {
    uint256 public currentL2BlockNumber;

    constructor(
        uint256 _block
    ) {
        currentL2BlockNumber = _block;
    }
}

/// @dev MessageService that always fails
contract FailingMessageService {
    fallback() external payable {
        revert("service error");
    }
}

contract LineaBridgeAdapterTest is Test {
    LineaBridgeAdapter public adapter;
    MockLineaMessageService public msgService;
    MockLineaRollup public rollup;
    address tokenBridge = makeAddr("tokenBridge");

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        msgService = new MockLineaMessageService();
        rollup = new MockLineaRollup(12_345);

        adapter = new LineaBridgeAdapter(address(msgService), tokenBridge, address(rollup), admin);

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        vm.stopPrank();
    }

    // ── Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsStorage() public view {
        assertEq(adapter.messageService(), address(msgService));
        assertEq(adapter.tokenBridge(), tokenBridge);
        assertEq(adapter.rollup(), address(rollup));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(keccak256("GUARDIAN_ROLE"), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new LineaBridgeAdapter(address(msgService), tokenBridge, address(rollup), address(0));
    }

    function test_constructor_revert_zeroMessageService() public {
        vm.expectRevert("Invalid message service");
        new LineaBridgeAdapter(address(0), tokenBridge, address(rollup), admin);
    }

    // ── Constants
    // ────────────────────────────────────────────────

    function test_constants() public view {
        assertEq(adapter.LINEA_MAINNET_CHAIN_ID(), 59_144);
        assertEq(adapter.LINEA_SEPOLIA_CHAIN_ID(), 59_141);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.DEFAULT_MESSAGE_FEE(), 0.001 ether);
        assertEq(adapter.MAX_PROOF_SIZE(), 32_768);
    }

    // ── Bridge Interface
    // ─────────────────────────────────────────

    function test_chainId() public view {
        assertEq(adapter.chainId(), 59_144);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Linea");
    }

    function test_isConfigured_false_noHub() public view {
        assertFalse(adapter.isConfigured());
    }

    function test_isConfigured_true() public {
        vm.prank(admin);
        adapter.setSoulHubL2(makeAddr("hub"));
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── Configuration
    // ────────────────────────────────────────────

    function test_configureLineaBridge() public {
        address newSvc = makeAddr("newSvc");
        address newTB = makeAddr("newTB");
        address newRU = makeAddr("newRU");

        vm.prank(operator);
        adapter.configureLineaBridge(newSvc, newTB, newRU);

        assertEq(adapter.messageService(), newSvc);
        assertEq(adapter.tokenBridge(), newTB);
        assertEq(adapter.rollup(), newRU);
    }

    function test_configureLineaBridge_emitsEvent() public {
        vm.prank(operator);
        vm.expectEmit(false, false, false, true);
        emit LineaBridgeAdapter.BridgeConfigured(makeAddr("s"), makeAddr("t"), makeAddr("r"));
        adapter.configureLineaBridge(makeAddr("s"), makeAddr("t"), makeAddr("r"));
    }

    function test_configureLineaBridge_revert_zeroMessageService() public {
        vm.prank(operator);
        vm.expectRevert("Invalid message service");
        adapter.configureLineaBridge(address(0), tokenBridge, address(rollup));
    }

    function test_configureLineaBridge_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.configureLineaBridge(makeAddr("s"), makeAddr("t"), makeAddr("r"));
    }

    function test_setSoulHubL2() public {
        vm.prank(admin);
        adapter.setSoulHubL2(makeAddr("hub"));
        assertEq(adapter.soulHubL2(), makeAddr("hub"));
    }

    function test_setSoulHubL2_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setSoulHubL2(address(0));
    }

    function test_setProofRegistry() public {
        vm.prank(admin);
        adapter.setProofRegistry(makeAddr("reg"));
        assertEq(adapter.proofRegistry(), makeAddr("reg"));
    }

    function test_setProofRegistry_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setProofRegistry(address(0));
    }

    // ── sendMessage
    // ──────────────────────────────────────────────

    function test_sendMessage_success() public {
        address target = makeAddr("target");
        bytes memory data = hex"aabb";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(target, data, 0.001 ether);

        assertTrue(msgHash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_defaultFee() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);
        // fee defaults to DEFAULT_MESSAGE_FEE = 0.001 ether
        assertEq(msgService.lastFee(), 0.001 ether);
    }

    function test_sendMessage_customFee() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        adapter.sendMessage{ value: 0.05 ether }(makeAddr("t"), hex"aa", 0.005 ether);
        assertEq(msgService.lastFee(), 0.005 ether);
    }

    function test_sendMessage_storesRecord() public {
        address target = makeAddr("target");
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(target, hex"aabb", 0);

        (
            LineaBridgeAdapter.MessageStatus status,
            address recordTarget,
            uint256 ts,
            uint256 msgNum,
            uint256 fee
        ) = adapter.messages(msgHash);
        assertEq(uint8(status), uint8(LineaBridgeAdapter.MessageStatus.SENT));
        assertEq(recordTarget, target);
        assertTrue(ts > 0);
        assertEq(msgNum, 0);
        assertEq(fee, 0.001 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.deal(operator, 10 ether);
        vm.startPrank(operator);
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"bb", 0);
        vm.stopPrank();
        assertEq(adapter.messageNonce(), 2);
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage{ value: 0.01 ether }(address(0), hex"aa", 0);
    }

    function test_sendMessage_revert_dataTooLarge() public {
        bytes memory bigData = new bytes(32_769);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Data too large");
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), bigData, 0);
    }

    function test_sendMessage_revert_insufficientFee() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Insufficient fee");
        adapter.sendMessage{ value: 0.0001 ether }(makeAddr("t"), hex"aa", 0.01 ether);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_revert_serviceFailure() public {
        FailingMessageService failSvc = new FailingMessageService();
        vm.prank(operator);
        adapter.configureLineaBridge(address(failSvc), tokenBridge, address(rollup));

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("MessageService call failed");
        adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);
    }

    // ── claimMessage
    // ─────────────────────────────────────────────

    function test_claimMessage_success() public {
        // Send first
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aabb", 0);

        // Claim
        bytes32[] memory merkle = new bytes32[](1);
        merkle[0] = bytes32(uint256(42));
        LineaBridgeAdapter.ClaimProof memory proof = LineaBridgeAdapter.ClaimProof({
            messageNumber: 100, leafIndex: 0, merkleProof: merkle
        });

        vm.prank(relayer);
        adapter.claimMessage(msgHash, proof);

        (LineaBridgeAdapter.MessageStatus status,,,,) = adapter.messages(msgHash);
        assertEq(uint8(status), uint8(LineaBridgeAdapter.MessageStatus.CLAIMED));
        assertTrue(adapter.processedMessages(100));
    }

    function test_claimMessage_emitsEvent() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aabb", 0);

        bytes32[] memory merkle = new bytes32[](0);
        LineaBridgeAdapter.ClaimProof memory proof =
            LineaBridgeAdapter.ClaimProof({ messageNumber: 50, leafIndex: 0, merkleProof: merkle });

        vm.prank(relayer);
        vm.expectEmit(true, true, false, true);
        emit LineaBridgeAdapter.MessageClaimed(msgHash, relayer, 50);
        adapter.claimMessage(msgHash, proof);
    }

    function test_claimMessage_revert_invalidState() public {
        bytes32[] memory merkle = new bytes32[](0);
        LineaBridgeAdapter.ClaimProof memory proof =
            LineaBridgeAdapter.ClaimProof({ messageNumber: 1, leafIndex: 0, merkleProof: merkle });

        vm.prank(relayer);
        vm.expectRevert("Invalid message state");
        adapter.claimMessage(bytes32(uint256(999)), proof);
    }

    function test_claimMessage_revert_alreadyClaimed() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aabb", 0);

        bytes32[] memory merkle = new bytes32[](0);
        LineaBridgeAdapter.ClaimProof memory proof =
            LineaBridgeAdapter.ClaimProof({ messageNumber: 10, leafIndex: 0, merkleProof: merkle });

        vm.prank(relayer);
        adapter.claimMessage(msgHash, proof);

        // re-send same messageNumber with different msgHash
        vm.prank(operator);
        bytes32 msgHash2 = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"ccdd", 0);
        vm.prank(relayer);
        vm.expectRevert("Already claimed");
        adapter.claimMessage(msgHash2, proof);
    }

    function test_claimMessage_revert_notRelayer() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aa", 0);

        bytes32[] memory merkle = new bytes32[](0);
        LineaBridgeAdapter.ClaimProof memory proof =
            LineaBridgeAdapter.ClaimProof({ messageNumber: 1, leafIndex: 0, merkleProof: merkle });

        vm.prank(operator);
        vm.expectRevert();
        adapter.claimMessage(msgHash, proof);
    }

    // ── verifyMessage
    // ────────────────────────────────────────────

    function test_verifyMessage_emptyProof() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), ""));
    }

    function test_verifyMessage_claimedMessage() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{ value: 0.01 ether }(makeAddr("t"), hex"aabb", 0);

        bytes32[] memory merkle = new bytes32[](0);
        LineaBridgeAdapter.ClaimProof memory proof =
            LineaBridgeAdapter.ClaimProof({ messageNumber: 5, leafIndex: 0, merkleProof: merkle });
        vm.prank(relayer);
        adapter.claimMessage(msgHash, proof);

        assertTrue(adapter.verifyMessage(msgHash, hex"01"));
    }

    // ── getLastFinalizedBlock
    // ────────────────────────────────────

    function test_getLastFinalizedBlock() public view {
        assertEq(adapter.getLastFinalizedBlock(), 12_345);
    }

    function test_getLastFinalizedBlock_zeroRollup() public {
        LineaBridgeAdapter a2 =
            new LineaBridgeAdapter(address(msgService), tokenBridge, address(0), admin);
        assertEq(a2.getLastFinalizedBlock(), 0);
    }

    // ── Admin: Pause / Unpause / EmergencyWithdraw
    // ───────────────

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

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 3 ether);
        assertEq(recipient.balance, 3 ether);
    }

    function test_emergencyWithdrawETH_revert_zeroRecipient() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        vm.expectRevert("Invalid recipient");
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawETH_revert_insufficientBalance() public {
        vm.prank(admin);
        vm.expectRevert("Insufficient balance");
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 99 ether);
    }

    // ── receive
    // ──────────────────────────────────────────────────

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok,) = address(adapter).call{ value: 0.5 ether }("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 0.5 ether);
    }

    // ── Fuzz
    // ─────────────────────────────────────────────────────

    function testFuzz_sendMessage_fees(
        uint256 fee
    ) public {
        fee = bound(fee, 0.001 ether, 1 ether);
        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{ value: fee }(makeAddr("t"), hex"aa", fee);
        assertTrue(hash != bytes32(0));
    }
}
