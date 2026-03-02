// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/PolkadotBridgeAdapter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @dev Mock Snowbridge gateway for testing
contract MockSnowbridge is ISnowbridge {
    bytes32 public mockMessageId = bytes32(uint256(0xD07));
    uint256 public mockFee = 0.001 ether;
    bytes32 public mockCommitment = bytes32(uint256(0xBEEF));

    function sendMessage(
        uint32 /* paraId */,
        bytes calldata /* payload */
    ) external payable returns (bytes32 messageId) {
        return mockMessageId;
    }

    function quoteSendFee(
        uint32 /* paraId */
    ) external view returns (uint256 fee) {
        return mockFee;
    }

    function currentBeefyCommitment()
        external
        view
        returns (bytes32 commitment)
    {
        return mockCommitment;
    }

    function setMessageId(bytes32 _id) external {
        mockMessageId = _id;
    }

    function setFee(uint256 _fee) external {
        mockFee = _fee;
    }

    function setCommitment(bytes32 _commitment) external {
        mockCommitment = _commitment;
    }
}

/// @dev Mock BEEFY finality proof verifier for testing
contract MockBeefyVerifier is IBeefyVerifier {
    bool public shouldVerify = true;
    bytes32 public mockAuthoritySetHash = bytes32(uint256(0xABCD));

    function verifyBeefyProof(
        bytes calldata /* proof */,
        bytes calldata /* data */
    ) external returns (bool valid) {
        return shouldVerify;
    }

    function authoritySetHash() external view returns (bytes32 hash) {
        return mockAuthoritySetHash;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }

    function setAuthoritySetHash(bytes32 _hash) external {
        mockAuthoritySetHash = _hash;
    }
}

/// @dev Mock ERC20 for testing emergency withdrawals
contract MockERC20Polkadot {
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

contract PolkadotBridgeAdapterTest is Test {
    PolkadotBridgeAdapter public adapter;
    MockSnowbridge public mockSnowbridge;
    MockBeefyVerifier public mockVerifier;
    MockERC20Polkadot public mockToken;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public pauser = makeAddr("pauser");
    address public user = makeAddr("user");

    bytes public constant DUMMY_PAYLOAD = hex"010203040506";
    bytes public constant DUMMY_PROOF = hex"AABBCCDD";
    uint32 public constant ASSET_HUB = 1000;

    function setUp() public {
        mockSnowbridge = new MockSnowbridge();
        mockVerifier = new MockBeefyVerifier();
        mockToken = new MockERC20Polkadot();

        adapter = new PolkadotBridgeAdapter(
            address(mockSnowbridge),
            address(mockVerifier),
            admin
        );

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
        assertEq(address(adapter.snowbridge()), address(mockSnowbridge));
        assertEq(address(adapter.beefyVerifier()), address(mockVerifier));
        assertEq(adapter.targetParaId(), 1000);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
        new PolkadotBridgeAdapter(
            address(mockSnowbridge),
            address(mockVerifier),
            address(0)
        );
    }

    function test_constructor_revert_zeroSnowbridge() public {
        vm.expectRevert(PolkadotBridgeAdapter.InvalidSnowbridge.selector);
        new PolkadotBridgeAdapter(address(0), address(mockVerifier), admin);
    }

    function test_constructor_revert_zeroVerifier() public {
        vm.expectRevert(PolkadotBridgeAdapter.InvalidVerifier.selector);
        new PolkadotBridgeAdapter(address(mockSnowbridge), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.POLKADOT_CHAIN_ID(), 6100);
        assertEq(adapter.DEFAULT_PARA_ID(), 1000);
        assertEq(adapter.FINALITY_BLOCKS(), 30);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.MIN_PROOF_SIZE(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 6100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Polkadot");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 30);
    }

    function test_getBeefyCommitment() public view {
        assertEq(adapter.getBeefyCommitment(), bytes32(uint256(0xBEEF)));
    }

    /*//////////////////////////////////////////////////////////////
                    CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setSnowbridge() public {
        address newBridge = makeAddr("newBridge");
        vm.prank(admin);
        adapter.setSnowbridge(newBridge);
        assertEq(address(adapter.snowbridge()), newBridge);
    }

    function test_setSnowbridge_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidSnowbridge.selector);
        adapter.setSnowbridge(address(0));
    }

    function test_setBeefyVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        adapter.setBeefyVerifier(newVerifier);
        assertEq(address(adapter.beefyVerifier()), newVerifier);
    }

    function test_setBeefyVerifier_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidVerifier.selector);
        adapter.setBeefyVerifier(address(0));
    }

    function test_setTargetParaId() public {
        vm.prank(admin);
        adapter.setTargetParaId(2000);
        assertEq(adapter.targetParaId(), 2000);
    }

    function test_setTargetParaId_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
        adapter.setTargetParaId(0);
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
            abi.encodeWithSelector(
                PolkadotBridgeAdapter.FeeTooHigh.selector,
                101
            )
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    SEND MESSAGE TESTS (ZASEON → POLKADOT)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            ASSET_HUB,
            DUMMY_PAYLOAD
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_tracksValueBridged() public {
        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(ASSET_HUB, DUMMY_PAYLOAD);
        assertEq(adapter.totalValueBridged(), 1 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.deal(operator, 10 ether);
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, DUMMY_PAYLOAD);
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, DUMMY_PAYLOAD);
        vm.stopPrank();
        assertEq(adapter.totalMessagesSent(), 2);
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(ASSET_HUB, DUMMY_PAYLOAD);

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_sendMessage_revert_zeroParaId() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(0, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, "");
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolkadotBridgeAdapter.InsufficientFee.selector,
                1.001 ether, // gateway fee (0.001) + min fee (1)
                0.5 ether
            )
        );
        adapter.sendMessage{value: 0.5 ether}(ASSET_HUB, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        bytes memory bigPayload = new bytes(10_001);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, bigPayload);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.sendMessage{value: 0.01 ether}(ASSET_HUB, DUMMY_PAYLOAD);
    }

    /*//////////////////////////////////////////////////////////////
                    RECEIVE MESSAGE TESTS (POLKADOT → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 commitment = bytes32(uint256(0x1234));
        bytes32 nullifier = bytes32(uint256(0x5678));
        uint32 paraId = 2000;
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(commitment);
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(paraId);
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveMessage(
            DUMMY_PROOF,
            pubInputs,
            DUMMY_PAYLOAD
        );

        assertTrue(msgHash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revert_invalidProof() public {
        mockVerifier.setShouldVerify(false);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 1000;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_notRelayer() public {
        uint256[] memory pubInputs = new uint256[](4);

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_replayProtection() public {
        bytes32 nullifier = bytes32(uint256(0x5678));
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(bytes32(uint256(0x1234)));
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(uint32(1000));
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        adapter.receiveMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);

        // Same nullifier → should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolkadotBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 1000;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.receiveMessage(DUMMY_PROOF, pubInputs, DUMMY_PAYLOAD);
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
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            "",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        // mockSnowbridge.quoteSendFee() = 0.001 ether, minMessageFee = 0
        assertEq(fee, 0.001 ether);
    }

    function test_estimateFee_withMinFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.005 ether);

        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        assertEq(fee, 0.006 ether); // 0.001 + 0.005
    }

    function test_isMessageVerified_sentMessage() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            ASSET_HUB,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);
        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 0x1234;
        pubInputs[1] = 0x5678;
        pubInputs[2] = 1000;
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
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
        adapter.sendMessage{value: 2 ether}(ASSET_HUB, DUMMY_PAYLOAD);

        uint256 expectedFees = 0.01 ether; // 0.5% of 2 ETH

        address payable feeRecipient = payable(makeAddr("feeRecipient"));
        vm.prank(admin);
        adapter.withdrawFees(feeRecipient);
        assertEq(feeRecipient.balance, expectedFees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_withdrawFees_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("x"));
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(PolkadotBridgeAdapter.InvalidTarget.selector);
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

    function testFuzz_sendMessage_anyValidPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            ASSET_HUB,
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
            abi.encodeWithSelector(
                PolkadotBridgeAdapter.FeeTooHigh.selector,
                fee
            )
        );
        adapter.setBridgeFee(fee);
    }

    function testFuzz_setTargetParaId(uint32 paraId) public {
        vm.assume(paraId > 0);
        vm.prank(admin);
        adapter.setTargetParaId(paraId);
        assertEq(adapter.targetParaId(), paraId);
    }
}
