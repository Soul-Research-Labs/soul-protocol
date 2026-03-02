// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SecretBridgeAdapter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @dev Mock Secret Network Gateway for testing
contract MockSecretGateway is ISecretGateway {
    bytes32 public mockTaskId = bytes32(uint256(0x5EC1));
    uint256 public mockFee = 0.001 ether;
    uint256 public mockNonce = 0;

    function send(
        bytes calldata /*routingInfo*/,
        bytes calldata /*payload*/
    ) external payable returns (bytes32 taskId) {
        mockNonce++;
        return mockTaskId;
    }

    function estimateFee() external view returns (uint256 fee) {
        return mockFee;
    }

    function taskNonce() external view returns (uint256 nonce) {
        return mockNonce;
    }

    function setTaskId(bytes32 _id) external {
        mockTaskId = _id;
    }

    function setFee(uint256 _fee) external {
        mockFee = _fee;
    }
}

/// @dev Mock Secret TEE Attestation Verifier for testing
contract MockSecretVerifier is ISecretVerifier {
    bool public shouldVerify = true;
    bytes32 public mockValidatorSetHash = bytes32(uint256(0xAA11));

    function verifyAttestation(
        bytes calldata /*attestation*/,
        bytes calldata /*data*/
    ) external returns (bool valid) {
        return shouldVerify;
    }

    function validatorSetHash() external view returns (bytes32 hash) {
        return mockValidatorSetHash;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }

    function setValidatorSetHash(bytes32 _hash) external {
        mockValidatorSetHash = _hash;
    }
}

/// @dev Mock ERC20 for testing emergency withdrawals
contract MockERC20Secret {
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

contract SecretBridgeAdapterTest is Test {
    SecretBridgeAdapter public adapter;
    MockSecretGateway public mockGateway;
    MockSecretVerifier public mockVerifier;
    MockERC20Secret public mockToken;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public pauser = makeAddr("pauser");
    address public user = makeAddr("user");

    bytes public constant DUMMY_ROUTING = hex"736563726574317878787878";
    bytes public constant DUMMY_PAYLOAD = hex"010203040506";
    bytes public constant DUMMY_ATTESTATION = hex"AABBCCDD";

    function setUp() public {
        mockGateway = new MockSecretGateway();
        mockVerifier = new MockSecretVerifier();
        mockToken = new MockERC20Secret();

        adapter = new SecretBridgeAdapter(
            address(mockGateway),
            address(mockVerifier),
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
        assertEq(address(adapter.secretGateway()), address(mockGateway));
        assertEq(address(adapter.secretVerifier()), address(mockVerifier));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
        new SecretBridgeAdapter(
            address(mockGateway),
            address(mockVerifier),
            address(0)
        );
    }

    function test_constructor_revert_zeroGateway() public {
        vm.expectRevert(SecretBridgeAdapter.InvalidGateway.selector);
        new SecretBridgeAdapter(address(0), address(mockVerifier), admin);
    }

    function test_constructor_revert_zeroVerifier() public {
        vm.expectRevert(SecretBridgeAdapter.InvalidVerifier.selector);
        new SecretBridgeAdapter(address(mockGateway), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.SECRET_CHAIN_ID(), 5100);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.MIN_ATTESTATION_SIZE(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 5100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Secret Network");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    function test_getValidatorSetHash() public view {
        assertEq(adapter.getValidatorSetHash(), bytes32(uint256(0xAA11)));
    }

    /*//////////////////////////////////////////////////////////////
                    CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setSecretGateway() public {
        address newGateway = makeAddr("newGateway");
        vm.prank(admin);
        adapter.setSecretGateway(newGateway);
        assertEq(address(adapter.secretGateway()), newGateway);
    }

    function test_setSecretGateway_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(SecretBridgeAdapter.InvalidGateway.selector);
        adapter.setSecretGateway(address(0));
    }

    function test_setSecretVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        adapter.setSecretVerifier(newVerifier);
        assertEq(address(adapter.secretVerifier()), newVerifier);
    }

    function test_setSecretVerifier_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(SecretBridgeAdapter.InvalidVerifier.selector);
        adapter.setSecretVerifier(address(0));
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
            abi.encodeWithSelector(SecretBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    SEND MESSAGE TESTS (ZASEON → SECRET)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            DUMMY_ROUTING,
            DUMMY_PAYLOAD
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_tracksValueBridged() public {
        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
        assertEq(adapter.totalValueBridged(), 1 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.deal(operator, 10 ether);
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
        vm.stopPrank();
        assertEq(adapter.totalMessagesSent(), 2);
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_sendMessage_revert_emptyRouting() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}("", DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SecretBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, "");
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                SecretBridgeAdapter.InsufficientFee.selector,
                1 ether, // required
                0.5 ether // provided
            )
        );
        adapter.sendMessage{value: 0.5 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        bytes memory bigPayload = new bytes(10_001);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SecretBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, bigPayload);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.sendMessage{value: 0.01 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);
    }

    /*//////////////////////////////////////////////////////////////
                    RECEIVE MESSAGE TESTS (SECRET → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 valSetHash = bytes32(uint256(0x1234));
        bytes32 nullifier = bytes32(uint256(0x5678));
        bytes32 taskIdOut = bytes32(uint256(0x9ABC));
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(valSetHash);
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(taskIdOut);
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        bytes32 msgHash = adapter.receiveMessage(
            DUMMY_ATTESTATION,
            pubInputs,
            DUMMY_PAYLOAD
        );

        assertTrue(msgHash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revert_invalidAttestation() public {
        mockVerifier.setShouldVerify(false);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 3;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(SecretBridgeAdapter.InvalidAttestation.selector);
        adapter.receiveMessage(DUMMY_ATTESTATION, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_notRelayer() public {
        uint256[] memory pubInputs = new uint256[](4);

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(DUMMY_ATTESTATION, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_replayProtection() public {
        bytes32 nullifier = bytes32(uint256(0x5678));
        bytes32 payloadHash = keccak256(DUMMY_PAYLOAD);

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = uint256(bytes32(uint256(0x1234)));
        pubInputs[1] = uint256(nullifier);
        pubInputs[2] = uint256(bytes32(uint256(0x9ABC)));
        pubInputs[3] = uint256(payloadHash);

        vm.prank(relayer);
        adapter.receiveMessage(DUMMY_ATTESTATION, pubInputs, DUMMY_PAYLOAD);

        // Same nullifier → should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SecretBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(DUMMY_ATTESTATION, pubInputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 3;
        pubInputs[3] = uint256(keccak256(DUMMY_PAYLOAD));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.receiveMessage(DUMMY_ATTESTATION, pubInputs, DUMMY_PAYLOAD);
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
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(SecretBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            "",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        // mockGateway.estimateFee() = 0.001 ether, minMessageFee = 0
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
            DUMMY_ROUTING,
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
        bytes32 hash = adapter.receiveMessage(
            DUMMY_ATTESTATION,
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
        adapter.sendMessage{value: 2 ether}(DUMMY_ROUTING, DUMMY_PAYLOAD);

        uint256 expectedFees = 0.01 ether; // 0.5% of 2 ETH

        address payable feeRecipient = payable(makeAddr("feeRecipient"));
        vm.prank(admin);
        adapter.withdrawFees(feeRecipient);
        assertEq(feeRecipient.balance, expectedFees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_withdrawFees_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("x"));
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(SecretBridgeAdapter.InvalidTarget.selector);
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
            DUMMY_ROUTING,
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
            abi.encodeWithSelector(SecretBridgeAdapter.FeeTooHigh.selector, fee)
        );
        adapter.setBridgeFee(fee);
    }
}
