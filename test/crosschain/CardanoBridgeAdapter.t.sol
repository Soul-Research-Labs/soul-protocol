// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/CardanoBridgeAdapter.sol";

/// @dev Mock Wormhole Core contract for Cardano adapter tests
contract MockWormholeCoreCardano {
    uint64 public sequenceCounter;
    uint256 public messageFeeValue;

    bytes public lastPayload;
    uint32 public lastNonce;
    uint8 public lastConsistencyLevel;

    IWormholeStructsCardano.VM public mockVM;
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
            IWormholeStructsCardano.VM memory vm_,
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

/// @dev Mock Wormhole Token Bridge for Cardano adapter tests
contract MockWormholeTokenBridgeCardano {
    uint64 public sequenceCounter;

    function transferTokens(
        address,
        uint256,
        uint16,
        bytes32,
        uint256,
        uint32
    ) external payable returns (uint64 sequence) {
        sequence = sequenceCounter++;
    }

    function completeTransfer(bytes memory) external {}
}

/// @dev Minimal ERC-20 mock for emergency withdrawal tests
contract MockERC20Cardano {
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

    function totalSupply() external pure returns (uint256) {
        return type(uint256).max;
    }
}

contract CardanoBridgeAdapterTest is Test {
    CardanoBridgeAdapter public adapter;
    MockWormholeCoreCardano public mockCore;
    MockWormholeTokenBridgeCardano public mockTokenBridge;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @dev Example Cardano validator script hash (padded to bytes32)
    bytes32 constant CARDANO_VALIDATOR =
        bytes32(
            uint256(0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef01)
        );

    uint256 constant WORMHOLE_FEE = 0.001 ether;

    function setUp() public {
        mockCore = new MockWormholeCoreCardano(WORMHOLE_FEE);
        mockTokenBridge = new MockWormholeTokenBridgeCardano();

        adapter = new CardanoBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        adapter.setZaseonCardanoValidator(CARDANO_VALIDATOR);
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
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
        new CardanoBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            address(0)
        );
    }

    function test_constructor_revert_zeroWormholeCore() public {
        vm.expectRevert(CardanoBridgeAdapter.InvalidWormholeCore.selector);
        new CardanoBridgeAdapter(address(0), address(mockTokenBridge), admin);
    }

    function test_constructor_revert_zeroTokenBridge() public {
        vm.expectRevert(CardanoBridgeAdapter.InvalidTokenBridge.selector);
        new CardanoBridgeAdapter(address(mockCore), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.CARDANO_WORMHOLE_CHAIN_ID(), 15);
        assertEq(adapter.FINALITY_BLOCKS(), 20);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.CONSISTENCY_LEVEL_FINALIZED(), 200);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 15);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Cardano");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_isConfigured_false_noValidator() public {
        CardanoBridgeAdapter fresh = new CardanoBridgeAdapter(
            address(mockCore),
            address(mockTokenBridge),
            admin
        );
        assertFalse(fresh.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 20);
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
        vm.expectRevert(CardanoBridgeAdapter.InvalidWormholeCore.selector);
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
        vm.expectRevert(CardanoBridgeAdapter.InvalidTokenBridge.selector);
        adapter.setWormholeTokenBridge(address(0));
    }

    function test_setZaseonCardanoValidator() public {
        bytes32 newVal = bytes32(uint256(42));
        vm.prank(admin);
        adapter.setZaseonCardanoValidator(newVal);
        assertEq(adapter.zaseonCardanoValidator(), newVal);
    }

    function test_setZaseonCardanoValidator_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(CardanoBridgeAdapter.InvalidCardanoValidator.selector);
        adapter.setZaseonCardanoValidator(bytes32(0));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revert_tooHigh() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                CardanoBridgeAdapter.FeeTooHigh.selector,
                101
            )
        );
        adapter.setBridgeFee(101);
    }

    function test_setBridgeFee_max() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);
        assertEq(adapter.bridgeFee(), 100);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    function test_setWhitelistedValidator() public {
        bytes32 val = bytes32(uint256(123));
        vm.prank(operator);
        adapter.setWhitelistedValidator(val, true);
        assertTrue(adapter.whitelistedValidators(val));
        assertTrue(adapter.isValidatorWhitelisted(val));

        vm.prank(operator);
        adapter.setWhitelistedValidator(val, false);
        assertFalse(adapter.whitelistedValidators(val));
    }

    /*//////////////////////////////////////////////////////////////
                      SEND MESSAGE (EVM → CARDANO)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.01 ether}(
            CARDANO_VALIDATOR,
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

        adapter.sendMessage{value: 0.01 ether}(CARDANO_VALIDATOR, payload);
        assertEq(adapter.senderNonces(operator), 1);

        adapter.sendMessage{value: 0.01 ether}(CARDANO_VALIDATOR, payload);
        assertEq(adapter.senderNonces(operator), 2);

        vm.stopPrank();
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"aa");
    }

    function test_sendMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(CardanoBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(CARDANO_VALIDATOR, hex"");
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        bytes memory largePayload = new bytes(10_001);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(CardanoBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.5 ether}(CARDANO_VALIDATOR, largePayload);
    }

    function test_sendMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 0.5 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.001 ether}(CARDANO_VALIDATOR, hex"aa");
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(CARDANO_VALIDATOR, hex"aa");
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(CARDANO_VALIDATOR, hex"aa");
    }

    function test_sendMessage_tracksValueBridged() public {
        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 0.5 ether}(CARDANO_VALIDATOR, payload);

        assertEq(adapter.totalValueBridged(), 0.5 ether);
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);

        bytes memory payload = hex"deadbeef";

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(CARDANO_VALIDATOR, payload);

        assertEq(adapter.accumulatedFees(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                     RECEIVE VAA (CARDANO → EVM)
    //////////////////////////////////////////////////////////////*/

    function test_receiveVAA_success() public {
        bytes32 vaaHash = keccak256("test_vaa_cardano");
        mockCore.setMockVAA(
            15, // Cardano chain ID
            CARDANO_VALIDATOR,
            1,
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

    function test_receiveVAA_whitelistedValidator() public {
        bytes32 otherValidator = bytes32(uint256(0xabcd));
        vm.prank(operator);
        adapter.setWhitelistedValidator(otherValidator, true);

        bytes32 vaaHash = keccak256("test_vaa_wv");
        mockCore.setMockVAA(15, otherValidator, 2, hex"1234", vaaHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveVAA(hex"bb");
        assertTrue(msgHash != bytes32(0));
    }

    function test_receiveVAA_revert_replayProtection() public {
        bytes32 vaaHash = keccak256("replay_vaa_cardano");
        mockCore.setMockVAA(15, CARDANO_VALIDATOR, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        adapter.receiveVAA(hex"aa");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                CardanoBridgeAdapter.VAAAlreadyConsumed.selector,
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
                CardanoBridgeAdapter.InvalidVAA.selector,
                "guardian verification failed"
            )
        );
        adapter.receiveVAA(hex"cc");
    }

    function test_receiveVAA_revert_wrongChain() public {
        bytes32 vaaHash = keccak256("wrong_chain_cardano");
        // Emitter chain = 1 (Solana) instead of 15 (Cardano)
        mockCore.setMockVAA(1, CARDANO_VALIDATOR, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                CardanoBridgeAdapter.UnauthorizedEmitter.selector,
                uint16(1),
                CARDANO_VALIDATOR
            )
        );
        adapter.receiveVAA(hex"dd");
    }

    function test_receiveVAA_revert_validatorNotWhitelisted() public {
        bytes32 unknownValidator = bytes32(uint256(0x9999));
        bytes32 vaaHash = keccak256("unknown_val");
        mockCore.setMockVAA(15, unknownValidator, 1, hex"aa", vaaHash);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                CardanoBridgeAdapter.ValidatorNotWhitelisted.selector,
                unknownValidator
            )
        );
        adapter.receiveVAA(hex"ee");
    }

    function test_receiveVAA_revert_notRelayer() public {
        bytes32 vaaHash = keccak256("test_cardano");
        mockCore.setMockVAA(15, CARDANO_VALIDATOR, 1, hex"aa", vaaHash);

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
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"aa",
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(CardanoBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            hex"",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), hex"dead");
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
            CARDANO_VALIDATOR,
            hex"deadbeef"
        );

        assertTrue(adapter.isMessageVerified(msgHash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 vaaHash = keccak256("delivered_cardano");
        mockCore.setMockVAA(15, CARDANO_VALIDATOR, 1, hex"aa", vaaHash);

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
        vm.prank(admin);
        adapter.setBridgeFee(100);

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(CARDANO_VALIDATOR, hex"aa");

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
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawERC20() public {
        address token = address(new MockERC20Cardano());
        deal(token, address(adapter), 100 ether);

        address recipient = makeAddr("tokenRecipient");

        vm.prank(admin);
        adapter.emergencyWithdrawERC20(token, recipient);

        assertEq(MockERC20Cardano(token).balanceOf(recipient), 100 ether);
    }

    function test_emergencyWithdrawERC20_revert_zeroToken() public {
        vm.prank(admin);
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("r"));
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(CardanoBridgeAdapter.InvalidTarget.selector);
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
            abi.encodeWithSelector(
                CardanoBridgeAdapter.FeeTooHigh.selector,
                fee
            )
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
            CARDANO_VALIDATOR,
            payload
        );
        assertTrue(hash != bytes32(0));
    }
}
