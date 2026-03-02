// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/AztecBridgeAdapter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @dev Mock Aztec Rollup Processor for testing
contract MockAztecRollupProcessor is IAztecRollupProcessor {
    bytes32 public mockStateHash = bytes32(uint256(0xABCD));

    function depositPendingFunds(
        uint256 /*assetId*/,
        uint256 /*amount*/,
        address /*owner*/
    ) external payable returns (bytes32) {
        return mockStateHash;
    }

    function rollupStateHash() external view returns (bytes32 root) {
        return mockStateHash;
    }

    function isRootFinalized(bytes32 /*root*/) external pure returns (bool) {
        return true;
    }

    function setStateHash(bytes32 _hash) external {
        mockStateHash = _hash;
    }
}

/// @dev Mock Aztec DeFi Bridge for testing
contract MockAztecDefiBridge is IAztecDefiBridge {
    bool public shouldSucceed = true;
    uint256 public mockOutputValue = 1 ether;

    function convert(
        uint256 /*inputAssetId*/,
        uint256 /*outputAssetId*/,
        uint256 /*totalInputValue*/,
        uint256 /*interactionNonce*/
    ) external payable returns (uint256 outputValueA, bool isAsync) {
        if (shouldSucceed) {
            return (mockOutputValue, false);
        }
        return (0, false);
    }

    function finalise(
        uint256 /*interactionNonce*/
    ) external pure returns (bool success) {
        return true;
    }

    function setShouldSucceed(bool _succeed) external {
        shouldSucceed = _succeed;
    }

    function setOutputValue(uint256 _value) external {
        mockOutputValue = _value;
    }
}

/// @dev Mock ERC20 for testing emergency withdrawals
contract MockERC20Aztec {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

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
}

/*//////////////////////////////////////////////////////////////
                          TEST CONTRACT
//////////////////////////////////////////////////////////////*/

contract AztecBridgeAdapterTest is Test {
    AztecBridgeAdapter public adapter;
    MockAztecRollupProcessor public mockProcessor;
    MockAztecDefiBridge public mockBridge;
    MockERC20Aztec public mockToken;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public pauser = makeAddr("pauser");
    address public user = makeAddr("user");

    bytes32 public constant DUMMY_COMMITMENT = bytes32(uint256(0xDEADBEEF));
    bytes public constant DUMMY_PAYLOAD = hex"010203040506";
    bytes public constant DUMMY_PROOF = hex"AABBCCDD";

    function setUp() public {
        mockProcessor = new MockAztecRollupProcessor();
        mockBridge = new MockAztecDefiBridge();
        mockToken = new MockERC20Aztec();

        adapter = new AztecBridgeAdapter(
            address(mockProcessor),
            address(mockBridge),
            admin
        );

        // Setup roles
        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.PAUSER_ROLE(), pauser);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsStorage() public view {
        assertEq(address(adapter.rollupProcessor()), address(mockProcessor));
        assertEq(address(adapter.defiBridge()), address(mockBridge));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        new AztecBridgeAdapter(
            address(mockProcessor),
            address(mockBridge),
            address(0)
        );
    }

    function test_constructor_revert_zeroProcessor() public {
        vm.expectRevert(AztecBridgeAdapter.InvalidProcessor.selector);
        new AztecBridgeAdapter(address(0), address(mockBridge), admin);
    }

    function test_constructor_revert_zeroBridge() public {
        vm.expectRevert(AztecBridgeAdapter.InvalidBridge.selector);
        new AztecBridgeAdapter(address(mockProcessor), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.AZTEC_CHAIN_ID(), 4100);
        assertEq(adapter.FINALITY_BLOCKS(), 15);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.HONK_PROOF_SIZE(), 512);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 4100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Aztec");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 15);
    }

    function test_getRollupStateHash() public view {
        assertEq(adapter.getRollupStateHash(), bytes32(uint256(0xABCD)));
    }

    /*//////////////////////////////////////////////////////////////
                    CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setRollupProcessor() public {
        address newProcessor = makeAddr("newProcessor");
        vm.prank(admin);
        adapter.setRollupProcessor(newProcessor);
        assertEq(address(adapter.rollupProcessor()), newProcessor);
    }

    function test_setRollupProcessor_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidProcessor.selector);
        adapter.setRollupProcessor(address(0));
    }

    function test_setRollupProcessor_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setRollupProcessor(makeAddr("x"));
    }

    function test_setDefiBridge() public {
        address newBridge = makeAddr("newBridge");
        vm.prank(admin);
        adapter.setDefiBridge(newBridge);
        assertEq(address(adapter.defiBridge()), newBridge);
    }

    function test_setDefiBridge_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidBridge.selector);
        adapter.setDefiBridge(address(0));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_max() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);
        assertEq(adapter.bridgeFee(), 100);
    }

    function test_setBridgeFee_revert_tooHigh() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(AztecBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT MESSAGE TESTS (ZASEON → AZTEC)
    //////////////////////////////////////////////////////////////*/

    function test_depositMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_depositMessage_tracksValueBridged() public {
        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.depositMessage{value: 1 ether}(DUMMY_COMMITMENT, DUMMY_PAYLOAD);
        assertEq(adapter.totalValueBridged(), 1 ether);
    }

    function test_depositMessage_incrementsNonce() public {
        vm.deal(operator, 10 ether);
        vm.startPrank(operator);
        adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        adapter.depositMessage{value: 0.01 ether}(
            bytes32(uint256(2)),
            DUMMY_PAYLOAD
        );
        vm.stopPrank();
        assertEq(adapter.totalMessagesSent(), 2);
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_depositMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.depositMessage{value: 1 ether}(DUMMY_COMMITMENT, DUMMY_PAYLOAD);

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_depositMessage_revert_zeroCommitment() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.depositMessage{value: 0.01 ether}(bytes32(0), DUMMY_PAYLOAD);
    }

    function test_depositMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(AztecBridgeAdapter.InvalidPayload.selector);
        adapter.depositMessage{value: 0.01 ether}(DUMMY_COMMITMENT, "");
    }

    function test_depositMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    function test_depositMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                AztecBridgeAdapter.InsufficientFee.selector,
                1 ether, // required
                0.5 ether // provided
            )
        );
        adapter.depositMessage{value: 0.5 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    function test_depositMessage_revert_payloadTooLarge() public {
        bytes memory bigPayload = new bytes(10_001);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(AztecBridgeAdapter.InvalidPayload.selector);
        adapter.depositMessage{value: 0.01 ether}(DUMMY_COMMITMENT, bigPayload);
    }

    function test_depositMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL MESSAGE TESTS (AZTEC → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_withdrawMessage_success() public {
        bytes32 dataRoot = bytes32(uint256(0x1234));
        bytes32 nullifier = bytes32(uint256(0x5678));
        bytes32 noteOut = bytes32(uint256(0x9ABC));
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(dataRoot);
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(noteOut);
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.withdrawMessage(
            DUMMY_PROOF,
            pubInputs,
            DUMMY_PAYLOAD
        );

        assertTrue(msgHash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_withdrawMessage_revert_invalidProof() public {
        // Make the bridge return 0 (invalid proof)
        mockBridge.setShouldSucceed(false);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 3;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(AztecBridgeAdapter.InvalidProof.selector);
        adapter.withdrawMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_withdrawMessage_revert_notRelayer() public {
        uint256[] memory pubInputs = new uint256[](4);

        vm.prank(user);
        vm.expectRevert();
        adapter.withdrawMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_withdrawMessage_revert_replayProtection() public {
        bytes32 nullifier = bytes32(uint256(0x5678));
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(bytes32(uint256(0x1234)));
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(bytes32(uint256(0x9ABC)));
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        adapter.withdrawMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);

        // Same nullifier → should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AztecBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.withdrawMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_withdrawMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 3;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.withdrawMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter COMPLIANCE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.1 ether}(
            makeAddr("target"),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
        assertTrue(id != bytes32(0));
        assertTrue(adapter.isMessageVerified(id));
    }

    function test_bridgeMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.bridgeMessage{value: 0.1 ether}(
            makeAddr("target"),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(AztecBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            "",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        assertEq(fee, 0); // minMessageFee defaults to 0
    }

    function test_estimateFee_withMinFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.005 ether);

        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        assertEq(fee, 0.005 ether);
    }

    function test_isMessageVerified_sentMessage() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);
        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 0x1234;
        pubInputs[1] = 0x5678;
        pubInputs[2] = 0x9ABC;
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        bytes32 hash = adapter.withdrawMessage(
            DUMMY_PROOF,
            pubInputs,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_unknownId() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(0xFFFF))));
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_pause() public {
        vm.prank(pauser);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_pause_revert_notPauser() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    function test_unpause() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_unpause_revert_notAdmin() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(user);
        vm.expectRevert();
        adapter.unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN / EMERGENCY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.depositMessage{value: 2 ether}(DUMMY_COMMITMENT, DUMMY_PAYLOAD);

        uint256 expectedFees = 0.01 ether; // 0.5% of 2 ETH

        address payable feeRecipient = payable(makeAddr("feeRecipient"));
        vm.prank(admin);
        adapter.withdrawFees(feeRecipient);
        assertEq(feeRecipient.balance, expectedFees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_withdrawFees_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.withdrawFees(payable(address(0)));
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 3 ether);
        assertEq(recipient.balance, 3 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(user), 1 ether);
    }

    function test_emergencyWithdrawETH_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawERC20() public {
        mockToken.mint(address(adapter), 100 ether);

        address recipient = makeAddr("recipient");
        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(mockToken), recipient);
        assertEq(mockToken.balanceOf(recipient), 100 ether);
    }

    function test_emergencyWithdrawERC20_revert_zeroToken() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("x"));
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(AztecBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(mockToken), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE ETH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 0.5 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        ROLE CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), keccak256("OPERATOR_ROLE"));
        assertEq(adapter.GUARDIAN_ROLE(), keccak256("GUARDIAN_ROLE"));
        assertEq(adapter.RELAYER_ROLE(), keccak256("RELAYER_ROLE"));
        assertEq(adapter.PAUSER_ROLE(), keccak256("PAUSER_ROLE"));
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositMessage_anyValidPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.depositMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            payload
        );
        assertTrue(hash != bytes32(0));
    }

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
            abi.encodeWithSelector(AztecBridgeAdapter.FeeTooHigh.selector, fee)
        );
        adapter.setBridgeFee(fee);
    }
}
