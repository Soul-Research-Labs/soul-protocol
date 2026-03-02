// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/MidnightBridgeAdapter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @dev Mock Midnight bridge relay for testing
contract MockMidnightBridge is IMidnightBridge {
    uint64 public sequenceCounter;
    uint256 public mockMessageFee = 0.001 ether;

    function publishMessage(
        uint32 /*nonce*/,
        bytes memory /*payload*/,
        uint8 /*proofLevel*/
    ) external payable returns (uint64 sequence) {
        sequenceCounter++;
        return sequenceCounter;
    }

    function messageFee() external view returns (uint256 fee) {
        return mockMessageFee;
    }

    function setMessageFee(uint256 _fee) external {
        mockMessageFee = _fee;
    }
}

/// @dev Mock PLONK proof verifier for testing
contract MockMidnightProofVerifier is IMidnightProofVerifier {
    bool public shouldVerify = true;

    function verifyProof(
        bytes calldata /*proof*/,
        uint256[] calldata /*publicInputs*/
    ) external view returns (bool valid) {
        return shouldVerify;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

/// @dev Mock ERC20 for testing emergency withdrawals
contract MockERC20Midnight {
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

contract MidnightBridgeAdapterTest is Test {
    MidnightBridgeAdapter public adapter;
    MockMidnightBridge public mockBridge;
    MockMidnightProofVerifier public mockVerifier;
    MockERC20Midnight public mockToken;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public pauser = makeAddr("pauser");
    address public user = makeAddr("user");

    bytes32 public constant DUMMY_CONTRACT = bytes32(uint256(0xDEADBEEF));
    bytes32 public constant DUMMY_ZASEON_CONTRACT =
        bytes32(uint256(0xCAFEBABE));
    bytes public constant DUMMY_PAYLOAD = hex"010203040506";
    bytes public constant DUMMY_PROOF = hex"AABBCCDD";

    function setUp() public {
        mockBridge = new MockMidnightBridge();
        mockVerifier = new MockMidnightProofVerifier();
        mockToken = new MockERC20Midnight();

        adapter = new MidnightBridgeAdapter(
            address(mockBridge),
            address(mockVerifier),
            admin
        );

        // Setup roles
        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.PAUSER_ROLE(), pauser);

        // Configure adapter
        adapter.setZaseonMidnightContract(DUMMY_ZASEON_CONTRACT);
        adapter.setWhitelistedContract(DUMMY_ZASEON_CONTRACT, true);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsStorage() public view {
        assertEq(address(adapter.midnightBridge()), address(mockBridge));
        assertEq(address(adapter.proofVerifier()), address(mockVerifier));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        new MidnightBridgeAdapter(
            address(mockBridge),
            address(mockVerifier),
            address(0)
        );
    }

    function test_constructor_revert_zeroBridge() public {
        vm.expectRevert(MidnightBridgeAdapter.InvalidBridge.selector);
        new MidnightBridgeAdapter(address(0), address(mockVerifier), admin);
    }

    function test_constructor_revert_zeroVerifier() public {
        vm.expectRevert(MidnightBridgeAdapter.InvalidProofVerifier.selector);
        new MidnightBridgeAdapter(address(mockBridge), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.MIDNIGHT_CHAIN_ID(), 2100);
        assertEq(adapter.FINALITY_BLOCKS(), 10);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.PROOF_LEVEL_FINALIZED(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 2100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Midnight");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_isConfigured_false_noContract() public {
        // Deploy fresh adapter without configuring zaseonMidnightContract
        MidnightBridgeAdapter freshAdapter = new MidnightBridgeAdapter(
            address(mockBridge),
            address(mockVerifier),
            admin
        );
        assertFalse(freshAdapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 10);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setMidnightBridge() public {
        address newBridge = makeAddr("newBridge");
        vm.prank(admin);
        adapter.setMidnightBridge(newBridge);
        assertEq(address(adapter.midnightBridge()), newBridge);
    }

    function test_setMidnightBridge_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setMidnightBridge(makeAddr("x"));
    }

    function test_setMidnightBridge_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidBridge.selector);
        adapter.setMidnightBridge(address(0));
    }

    function test_setProofVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(admin);
        adapter.setProofVerifier(newVerifier);
        assertEq(address(adapter.proofVerifier()), newVerifier);
    }

    function test_setProofVerifier_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidProofVerifier.selector);
        adapter.setProofVerifier(address(0));
    }

    function test_setZaseonMidnightContract() public {
        bytes32 newContract = bytes32(uint256(0x12345));
        vm.prank(admin);
        adapter.setZaseonMidnightContract(newContract);
        assertEq(adapter.zaseonMidnightContract(), newContract);
    }

    function test_setZaseonMidnightContract_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidMidnightContract.selector);
        adapter.setZaseonMidnightContract(bytes32(0));
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
                MidnightBridgeAdapter.FeeTooHigh.selector,
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

    function test_setWhitelistedContract() public {
        bytes32 contractHash = bytes32(uint256(0xBEEF));
        vm.prank(admin);
        adapter.setWhitelistedContract(contractHash, true);
        assertTrue(adapter.whitelistedContracts(contractHash));
    }

    /*//////////////////////////////////////////////////////////////
                 SEND MESSAGE (EVM → MIDNIGHT) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            DUMMY_CONTRACT,
            DUMMY_PAYLOAD
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_sendMessage_tracksValueBridged() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.deal(operator, 2 ether);
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);

        // 1 ether * 50 / 10000 = 0.005 ether protocol fee
        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(MidnightBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, "");
    }

    function test_sendMessage_revert_payloadTooLarge() public {
        vm.deal(operator, 1 ether);
        bytes memory bigPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(MidnightBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, bigPayload);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
    }

    function test_sendMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.0001 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (MIDNIGHT → EVM) TESTS
    //////////////////////////////////////////////////////////////*/

    function _buildPublicInputs(
        bytes32 sourceContract,
        uint64 sequence,
        bytes memory payload,
        bytes32 nullifier
    ) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](5);
        inputs[0] = uint256(sourceContract);
        inputs[1] = uint256(sequence);
        inputs[2] = uint256(keccak256(payload));
        inputs[3] = uint256(bytes32(uint256(0x1234))); // mock state root
        inputs[4] = uint256(nullifier);
        return inputs;
    }

    function test_receiveMessage_success() public {
        bytes32 nullifier = keccak256("nullifier1");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            DUMMY_PROOF,
            inputs,
            DUMMY_PAYLOAD
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function test_receiveMessage_whitelistedContract() public {
        bytes32 otherContract = bytes32(uint256(0xFEEDFACE));
        vm.prank(admin);
        adapter.setWhitelistedContract(otherContract, true);

        bytes32 nullifier = keccak256("nullifier2");
        uint256[] memory inputs = _buildPublicInputs(
            otherContract,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            DUMMY_PROOF,
            inputs,
            DUMMY_PAYLOAD
        );
        assertTrue(hash != bytes32(0));
    }

    function test_receiveMessage_revert_invalidProof() public {
        mockVerifier.setShouldVerify(false);

        bytes32 nullifier = keccak256("nullifier3");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        vm.expectRevert(MidnightBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_notRelayer() public {
        bytes32 nullifier = keccak256("nullifier4");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_replayProtection() public {
        bytes32 nullifier = keccak256("nullifier5");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);

        // Try to replay
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MidnightBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_contractNotWhitelisted() public {
        bytes32 unknownContract = bytes32(uint256(0x999));
        bytes32 nullifier = keccak256("nullifier6");
        uint256[] memory inputs = _buildPublicInputs(
            unknownContract,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MidnightBridgeAdapter.ContractNotWhitelisted.selector,
                unknownContract
            )
        );
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_receiveMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        bytes32 nullifier = keccak256("nullifier7");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    /*//////////////////////////////////////////////////////////////
                  IBridgeAdapter COMPLIANCE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
        assertTrue(id != bytes32(0));
    }

    function test_bridgeMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(MidnightBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            "",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        // mockBridge.messageFee() = 0.001 ether, minMessageFee = 0
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
            DUMMY_CONTRACT,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 nullifier = keccak256("nullifier_verify");
        uint256[] memory inputs = _buildPublicInputs(
            DUMMY_ZASEON_CONTRACT,
            1,
            DUMMY_PAYLOAD,
            nullifier
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            DUMMY_PROOF,
            inputs,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_unknownId() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(0xDEAD))));
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
        // Accumulate fees
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(DUMMY_CONTRACT, DUMMY_PAYLOAD);

        uint256 fees = adapter.accumulatedFees();
        assertTrue(fees > 0);

        address payable recipient = payable(makeAddr("feeRecipient"));
        vm.prank(admin);
        adapter.withdrawFees(recipient);

        assertEq(adapter.accumulatedFees(), 0);
        assertEq(recipient.balance, fees);
    }

    function test_withdrawFees_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.withdrawFees(payable(address(0)));
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 1 ether);
        address payable recipient = payable(makeAddr("ethRecipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 0.5 ether);
        assertEq(recipient.balance, 0.5 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(user), 0.1 ether);
    }

    function test_emergencyWithdrawETH_revert_zeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawETH(payable(address(0)), 0.1 ether);
    }

    function test_emergencyWithdrawERC20() public {
        mockToken.mint(address(adapter), 100 ether);

        address recipient = makeAddr("tokenRecipient");
        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(mockToken), recipient);
        assertEq(mockToken.balanceOf(recipient), 100 ether);
    }

    function test_emergencyWithdrawERC20_revert_zeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(mockToken), address(0));
    }

    function test_emergencyWithdrawERC20_revert_zeroToken() public {
        vm.prank(admin);
        vm.expectRevert(MidnightBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), makeAddr("x"));
    }

    /*//////////////////////////////////////////////////////////////
                       RECEIVE ETH TEST
    //////////////////////////////////////////////////////////////*/

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool sent, ) = address(adapter).call{value: 0.5 ether}("");
        assertTrue(sent);
        assertEq(address(adapter).balance, 0.5 ether);
    }

    /*//////////////////////////////////////////////////////////////
                       ROLE CONSTANTS TEST
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
            DUMMY_CONTRACT,
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
                MidnightBridgeAdapter.FeeTooHigh.selector,
                fee
            )
        );
        adapter.setBridgeFee(fee);
    }
}
