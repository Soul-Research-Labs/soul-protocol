// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SolanaBridgeAdapter.sol";

/// @dev Mock Wormhole Core contract that records calls and returns data
contract MockWormholeCore {
    uint64 public sequenceCounter;
    uint256 public messageFeeValue;

    // Track published messages for assertions
    bytes public lastPayload;
    uint32 public lastNonce;
    uint8 public lastConsistencyLevel;

    // Mock VAA response
    IWormholeStructs.VM public mockVM;
    bool public mockValid;
    string public mockReason;

    constructor(uint256 _messageFee) {
        messageFeeValue = _messageFee;
        mockValid = true;
        mockReason = "";
    }

    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence) {
        lastNonce = nonce;
        lastPayload = payload;
        lastConsistencyLevel = consistencyLevel;
        sequence = sequenceCounter++;
    }

    function parseAndVerifyVM(
        bytes calldata /* encodedVM */
    )
        external
        view
        returns (
            IWormholeStructs.VM memory vm_,
            bool valid,
            string memory reason
        )
    {
        vm_ = mockVM;
        valid = mockValid;
        reason = mockReason;
    }

    function messageFee() external view returns (uint256) {
        return messageFeeValue;
    }

    // Helper: set mock VAA response
    function setMockVAA(
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        bytes memory payload,
        bytes32 hash_
    ) external {
        mockVM.version = 1;
        mockVM.timestamp = uint32(block.timestamp);
        mockVM.nonce = 0;
        mockVM.emitterChainId = emitterChainId;
        mockVM.emitterAddress = emitterAddress;
        mockVM.sequence = sequence;
        mockVM.consistencyLevel = 200;
        mockVM.payload = payload;
        mockVM.guardianSetIndex = 0;
        mockVM.hash = hash_;
    }

    function setMockValidity(bool _valid, string memory _reason) external {
        mockValid = _valid;
        mockReason = _reason;
    }

    function setMessageFee(uint256 _fee) external {
        messageFeeValue = _fee;
    }
}

/// @dev Mock Wormhole Token Bridge
contract MockWormholeTokenBridge {
    uint64 public sequenceCounter;

    function transferTokens(
        address /* token */,
        uint256 /* amount */,
        uint16 /* recipientChain */,
        bytes32 /* recipient */,
        uint256 /* arbiterFee */,
        uint32 /* nonce */
    ) external payable returns (uint64 sequence) {
        sequence = sequenceCounter++;
    }

    function completeTransfer(bytes memory /* encodedVM */) external {
        // no-op for testing
    }
}

contract SolanaBridgeAdapterTest is Test {
    SolanaBridgeAdapter public adapter;
    MockWormholeCore public mockCore;
    MockWormholeTokenBridge public mockTokenBridge;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    bytes32 constant SOLANA_PROGRAM =
        bytes32(
            uint256(
                0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
            )
        );

    uint256 constant WORMHOLE_FEE = 0.001 ether;

    function setUp() public {
        mockCore = new MockWormholeCore(WORMHOLE_FEE);
        mockTokenBridge = new MockWormholeTokenBridge();

        adapter = new SolanaBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        adapter.setZaseonSolanaProgram(SOLANA_PROGRAM);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsStorage() public view {
        assertEq(address(adapter.wormholeCore()), address(mockCore));
        assertEq(
            address(adapter.wormholeTokenBridge()),
            address(mockTokenBridge)
        );
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        new SolanaBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            address(0)
        );
    }

    function test_constructor_revert_zeroWormholeCore() public {
        vm.expectRevert(SolanaBridgeAdapter.InvalidWormholeCore.selector);
        new SolanaBridgeAdapter(address(0), address(mockTokenBridge), admin);
    }

    function test_constructor_revert_zeroTokenBridge() public {
        vm.expectRevert(SolanaBridgeAdapter.InvalidTokenBridge.selector);
        new SolanaBridgeAdapter(address(mockCore), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.SOLANA_WORMHOLE_CHAIN_ID(), 1);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.CONSISTENCY_LEVEL_FINALIZED(), 200);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 1);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Solana");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_isConfigured_false_noProgram() public {
        SolanaBridgeAdapter fresh = new SolanaBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            admin
        );
        assertFalse(fresh.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setWormholeCore() public {
        address newCore = makeAddr("newCore");
        vm.prank(admin);
        adapter.setWormholeCore(newCore);
        assertEq(address(adapter.wormholeCore()), newCore);
    }

    function test_setWormholeCore_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidWormholeCore.selector);
        adapter.setWormholeCore(address(0));
    }

    function test_setWormholeCore_revert_notAdmin() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setWormholeCore(makeAddr("x"));
    }

    function test_setWormholeTokenBridge() public {
        address newBridge = makeAddr("newBridge");
        vm.prank(admin);
        adapter.setWormholeTokenBridge(newBridge);
        assertEq(address(adapter.wormholeTokenBridge()), newBridge);
    }

    function test_setWormholeTokenBridge_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTokenBridge.selector);
        adapter.setWormholeTokenBridge(address(0));
    }

    function test_setZaseonSolanaProgram() public {
        bytes32 newProg = bytes32(uint256(42));
        vm.prank(admin);
        adapter.setZaseonSolanaProgram(newProg);
        assertEq(adapter.zaseonSolanaProgram(), newProg);
    }

    function test_setZaseonSolanaProgram_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidSolanaProgram.selector);
        adapter.setZaseonSolanaProgram(bytes32(0));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revert_tooHigh() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SolanaBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setBridgeFee_max() public {
        vm.prank(admin);
        adapter.setBridgeFee(100); // 1% max
        assertEq(adapter.bridgeFee(), 100);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    function test_setWhitelistedProgram() public {
        bytes32 prog = bytes32(uint256(123));
        vm.prank(operator);
        adapter.setWhitelistedProgram(prog, true);
        assertTrue(adapter.whitelistedPrograms(prog));
        assertTrue(adapter.isProgramWhitelisted(prog));

        vm.prank(operator);
        adapter.setWhitelistedProgram(prog, false);
        assertFalse(adapter.whitelistedPrograms(prog));
    }

    /*//////////////////////////////////////////////////////////////
                      SEND MESSAGE (EVM → SOLANA)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            SOLANA_PROGRAM,
            payload
        );

        assertTrue(msgHash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.senderNonces(operator), 1);
    }

    function test_sendMessage_incrementsNonce() public {
        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 2 ether);
        vm.startPrank(operator);

        adapter.sendMessage{value: 0.01 ether}(SOLANA_PROGRAM, payload);
        assertEq(adapter.senderNonces(operator), 1);

        adapter.sendMessage{value: 0.01 ether}(SOLANA_PROGRAM, payload);
        assertEq(adapter.senderNonces(operator), 2);

        vm.stopPrank();
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"aa");
    }

    function test_sendMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SolanaBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(SOLANA_PROGRAM, hex"");
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        bytes memory largePayload = new bytes(10_001);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SolanaBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.5 ether}(SOLANA_PROGRAM, largePayload);
    }

    function test_sendMessage_revert_insufficientFee() public {
        // Set min message fee to require more
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 0.5 ether);
        vm.prank(operator);
        vm.expectRevert(); // InsufficientFee
        adapter.sendMessage{value: 0.001 ether}(SOLANA_PROGRAM, hex"aa");
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(SOLANA_PROGRAM, hex"aa");
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(SOLANA_PROGRAM, hex"aa");
    }

    function test_sendMessage_tracksValueBridged() public {
        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 0.5 ether}(SOLANA_PROGRAM, payload);

        assertEq(adapter.totalValueBridged(), 0.5 ether);
    }

    function test_sendMessage_accumulatesFees() public {
        // Set bridge fee to 100 bps (1%)
        vm.prank(admin);
        adapter.setBridgeFee(100);

        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(SOLANA_PROGRAM, payload);

        // Protocol fee = 1 ether * 100 / 10000 = 0.01 ether
        assertEq(adapter.accumulatedFees(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                     RECEIVE VAA (SOLANA → EVM)
    //////////////////////////////////////////////////////////////*/

    function test_receiveVAA_success() public {
        bytes32 vaaHash = keccak256("test_vaa");
        mockCore.setMockVAA(
            1, // Solana chain ID
            SOLANA_PROGRAM, // emitter = zaseonSolanaProgram
            1, // sequence
            hex"aabbccdd",
            vaaHash
        );

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveVAA(hex"aa");

        assertTrue(msgHash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.usedVAAHashes(vaaHash));
        assertTrue(adapter.isVAAUsed(vaaHash));
    }

    function test_receiveVAA_whitelistedProgram() public {
        bytes32 otherProgram = bytes32(uint256(0xabcd));
        vm.prank(operator);
        adapter.setWhitelistedProgram(otherProgram, true);

        bytes32 vaaHash = keccak256("test_vaa_wp");
        mockCore.setMockVAA(1, otherProgram, 2, hex"1234", vaaHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveVAA(hex"bb");
        assertTrue(msgHash != bytes32(0));
    }

    function test_receiveVAA_revert_replayProtection() public {
        bytes32 vaaHash = keccak256("replay_vaa");
        mockCore.setMockVAA(1, SOLANA_PROGRAM, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        adapter.receiveVAA(hex"aa");

        // Second attempt with same VAA hash should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolanaBridgeAdapter.VAAAlreadyConsumed.selector,
                vaaHash
            )
        );
        adapter.receiveVAA(hex"bb");
    }

    function test_receiveVAA_revert_invalidVAA() public {
        mockCore.setMockValidity(false, "guardian verification failed");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolanaBridgeAdapter.InvalidVAA.selector,
                "guardian verification failed"
            )
        );
        adapter.receiveVAA(hex"cc");
    }

    function test_receiveVAA_revert_wrongChain() public {
        bytes32 vaaHash = keccak256("wrong_chain");
        // Set emitter chain to Ethereum (2) instead of Solana (1)
        mockCore.setMockVAA(2, SOLANA_PROGRAM, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolanaBridgeAdapter.UnauthorizedEmitter.selector,
                uint16(2),
                SOLANA_PROGRAM
            )
        );
        adapter.receiveVAA(hex"dd");
    }

    function test_receiveVAA_revert_programNotWhitelisted() public {
        bytes32 unknownProgram = bytes32(uint256(0x9999));
        bytes32 vaaHash = keccak256("unknown_prog");
        mockCore.setMockVAA(1, unknownProgram, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SolanaBridgeAdapter.ProgramNotWhitelisted.selector,
                unknownProgram
            )
        );
        adapter.receiveVAA(hex"ee");
    }

    function test_receiveVAA_revert_notRelayer() public {
        bytes32 vaaHash = keccak256("test");
        mockCore.setMockVAA(1, SOLANA_PROGRAM, 1, hex"aa", vaaHash);

        vm.prank(operator);
        vm.expectRevert();
        adapter.receiveVAA(hex"ff");
    }

    function test_receiveVAA_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveVAA(hex"ff");
    }

    /*//////////////////////////////////////////////////////////////
                     IBridgeAdapter COMPLIANCE
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        address target = makeAddr("target");

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgId = adapter.bridgeMessage{value: 0.01 ether}(
            target,
            hex"deadbeef",
            makeAddr("refund")
        );

        assertTrue(msgId != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_bridgeMessage_revert_notOperator() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        adapter.bridgeMessage(
            makeAddr("target"),
            hex"dead",
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"aa",
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SolanaBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            hex"",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), hex"dead");
        // Wormhole fee (0.001 ether) + minMessageFee (0)
        assertEq(fee, WORMHOLE_FEE);
    }

    function test_estimateFee_withMinFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);

        uint256 fee = adapter.estimateFee(makeAddr("target"), hex"dead");
        assertEq(fee, WORMHOLE_FEE + 0.01 ether);
    }

    function test_isMessageVerified_sentMessage() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            SOLANA_PROGRAM,
            hex"deadbeef"
        );

        assertTrue(adapter.isMessageVerified(msgHash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 vaaHash = keccak256("delivered");
        mockCore.setMockVAA(1, SOLANA_PROGRAM, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveVAA(hex"ab");

        assertTrue(adapter.isMessageVerified(msgHash));
    }

    function test_isMessageVerified_unknownId() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(999))));
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

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

    function test_pause_revert_notPauser() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.pause();
    }

    function test_unpause_revert_notAdmin() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN / EMERGENCY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawFees() public {
        // Set fee and send a message to accumulate fees
        vm.prank(admin);
        adapter.setBridgeFee(100); // 1%

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(SOLANA_PROGRAM, hex"aa");

        uint256 fees = adapter.accumulatedFees();
        assertTrue(fees > 0);

        address payable recipient = payable(makeAddr("feeRecipient"));
        vm.prank(admin);
        adapter.withdrawFees(recipient);

        assertEq(recipient.balance, fees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_withdrawFees_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.withdrawFees(payable(address(0)));
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 3 ether);

        assertEq(recipient.balance, 3 ether);
        assertEq(address(adapter).balance, 2 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    function test_emergencyWithdrawETH_revert_zeroAddress() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawERC20() public {
        // Create a mock ERC-20 (using deal cheatcode)
        address token = address(new MockERC20());
        deal(token, address(adapter), 100 ether);

        address recipient = makeAddr("tokenRecipient");

        vm.prank(admin);
        adapter.emergencyWithdrawERC20(token, recipient);

        assertEq(MockERC20(token).balanceOf(recipient), 100 ether);
    }

    function test_emergencyWithdrawERC20_revert_zeroToken() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("r"));
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(SolanaBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(makeAddr("token"), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        ROLE CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), OPERATOR_ROLE);
        assertEq(adapter.GUARDIAN_ROLE(), GUARDIAN_ROLE);
        assertEq(adapter.RELAYER_ROLE(), RELAYER_ROLE);
        assertEq(adapter.PAUSER_ROLE(), PAUSER_ROLE);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_setBridgeFee_withinBounds(uint256 fee) public {
        fee = bound(fee, 0, 100);
        vm.prank(admin);
        adapter.setBridgeFee(fee);
        assertEq(adapter.bridgeFee(), fee);
    }

    function testFuzz_setBridgeFee_reverts_aboveBounds(uint256 fee) public {
        fee = bound(fee, 101, type(uint256).max);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SolanaBridgeAdapter.FeeTooHigh.selector, fee)
        );
        adapter.setBridgeFee(fee);
    }

    function testFuzz_sendMessage_anyValidPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 1 ether}(
            SOLANA_PROGRAM,
            payload
        );
        assertTrue(hash != bytes32(0));
    }
}

/// @dev Minimal ERC-20 mock for emergency withdrawal tests
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    // Allow deal() cheatcode to work
    function totalSupply() external pure returns (uint256) {
        return type(uint256).max;
    }
}
