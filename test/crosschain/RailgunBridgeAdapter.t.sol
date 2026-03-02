// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/RailgunBridgeAdapter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

/// @dev Mock Railgun Smart Wallet for testing
contract MockRailgunSmartWallet is IRailgunSmartWallet {
    bytes32 public mockMerkleRoot = bytes32(uint256(0xAABB));

    function shield(
        bytes32[] calldata /*commitments*/,
        bytes calldata /*boundParams*/,
        uint256[] calldata /*fees*/
    ) external payable returns (bytes32 merkleRoot) {
        return mockMerkleRoot;
    }

    function merkleRoot() external view returns (bytes32 root) {
        return mockMerkleRoot;
    }

    function setMerkleRoot(bytes32 _root) external {
        mockMerkleRoot = _root;
    }
}

/// @dev Mock Railgun Relay Adapt for testing
contract MockRailgunRelayAdapt is IRailgunRelayAdapt {
    bool public shouldRelay = true;
    uint256 public mockRelayFee = 0.001 ether;

    function relay(
        bytes calldata /*proof*/,
        uint256[] calldata /*publicInputs*/
    ) external returns (bool success) {
        return shouldRelay;
    }

    function relayFee() external view returns (uint256 fee) {
        return mockRelayFee;
    }

    function setShouldRelay(bool _relay) external {
        shouldRelay = _relay;
    }

    function setRelayFee(uint256 _fee) external {
        mockRelayFee = _fee;
    }
}

/// @dev Mock ERC20 for testing emergency withdrawals
contract MockERC20Railgun {
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

contract RailgunBridgeAdapterTest is Test {
    RailgunBridgeAdapter public adapter;
    MockRailgunSmartWallet public mockWallet;
    MockRailgunRelayAdapt public mockRelay;
    MockERC20Railgun public mockToken;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public pauser = makeAddr("pauser");
    address public user = makeAddr("user");

    bytes32 public constant DUMMY_COMMITMENT = bytes32(uint256(0xDEADBEEF));
    bytes public constant DUMMY_PAYLOAD = hex"010203040506";
    bytes public constant DUMMY_PROOF = hex"AABBCCDD";

    function setUp() public {
        mockWallet = new MockRailgunSmartWallet();
        mockRelay = new MockRailgunRelayAdapt();
        mockToken = new MockERC20Railgun();

        adapter = new RailgunBridgeAdapter(
            address(mockWallet),
            address(mockRelay),
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
        assertEq(address(adapter.railgunWallet()), address(mockWallet));
        assertEq(address(adapter.railgunRelay()), address(mockRelay));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
        new RailgunBridgeAdapter(
            address(mockWallet),
            address(mockRelay),
            address(0)
        );
    }

    function test_constructor_revert_zeroWallet() public {
        vm.expectRevert(RailgunBridgeAdapter.InvalidWallet.selector);
        new RailgunBridgeAdapter(address(0), address(mockRelay), admin);
    }

    function test_constructor_revert_zeroRelay() public {
        vm.expectRevert(RailgunBridgeAdapter.InvalidRelay.selector);
        new RailgunBridgeAdapter(address(mockWallet), address(0), admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.RAILGUN_CHAIN_ID(), 3100);
        assertEq(adapter.FINALITY_BLOCKS(), 12);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.GROTH16_PROOF_SIZE(), 256);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 3100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Railgun");
    }

    function test_isConfigured_true() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 12);
    }

    function test_getMerkleRoot() public view {
        assertEq(adapter.getMerkleRoot(), bytes32(uint256(0xAABB)));
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setRailgunWallet() public {
        address newWallet = makeAddr("newWallet");
        vm.prank(admin);
        adapter.setRailgunWallet(newWallet);
        assertEq(address(adapter.railgunWallet()), newWallet);
    }

    function test_setRailgunWallet_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setRailgunWallet(makeAddr("x"));
    }

    function test_setRailgunWallet_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(RailgunBridgeAdapter.InvalidWallet.selector);
        adapter.setRailgunWallet(address(0));
    }

    function test_setRailgunRelay() public {
        address newRelay = makeAddr("newRelay");
        vm.prank(admin);
        adapter.setRailgunRelay(newRelay);
        assertEq(address(adapter.railgunRelay()), newRelay);
    }

    function test_setRailgunRelay_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert(RailgunBridgeAdapter.InvalidRelay.selector);
        adapter.setRailgunRelay(address(0));
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
                RailgunBridgeAdapter.FeeTooHigh.selector,
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
               SHIELD MESSAGE (ZASEON → RAILGUN) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_shieldMessage_success() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_shieldMessage_tracksValueBridged() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_shieldMessage_incrementsNonce() public {
        vm.deal(operator, 2 ether);
        vm.startPrank(operator);
        adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_shieldMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.deal(operator, 2 ether);
        vm.prank(operator);
        adapter.shieldMessage{value: 1 ether}(DUMMY_COMMITMENT, DUMMY_PAYLOAD);

        // 1 ether * 50 / 10000 = 0.005 ether protocol fee
        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_shieldMessage_revert_zeroCommitment() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
        adapter.shieldMessage{value: 0.01 ether}(bytes32(0), DUMMY_PAYLOAD);
    }

    function test_shieldMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(RailgunBridgeAdapter.InvalidPayload.selector);
        adapter.shieldMessage{value: 0.01 ether}(DUMMY_COMMITMENT, "");
    }

    function test_shieldMessage_revert_payloadTooLarge() public {
        vm.deal(operator, 1 ether);
        bytes memory bigPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(RailgunBridgeAdapter.InvalidPayload.selector);
        adapter.shieldMessage{value: 0.01 ether}(DUMMY_COMMITMENT, bigPayload);
    }

    function test_shieldMessage_revert_notOperator() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    function test_shieldMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    function test_shieldMessage_revert_insufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.shieldMessage{value: 0.0001 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
    }

    /*//////////////////////////////////////////////////////////////
            UNSHIELD MESSAGE (RAILGUN → ZASEON) TESTS
    //////////////////////////////////////////////////////////////*/

    function _buildPublicInputs(
        bytes32 merkleRoot,
        bytes32 nullifier,
        bytes32 commitmentOut,
        bytes memory payload
    ) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(merkleRoot);
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(commitmentOut);
        inputs[3] = uint256(keccak256(payload));
        return inputs;
    }

    function test_unshieldMessage_success() public {
        bytes32 nullifier = keccak256("nullifier1");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(relayer);
        bytes32 hash = adapter.unshieldMessage(
            DUMMY_PROOF,
            inputs,
            DUMMY_PAYLOAD
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function test_unshieldMessage_revert_invalidProof() public {
        mockRelay.setShouldRelay(false);

        bytes32 nullifier = keccak256("nullifier2");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(relayer);
        vm.expectRevert(RailgunBridgeAdapter.InvalidProof.selector);
        adapter.unshieldMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_unshieldMessage_revert_notRelayer() public {
        bytes32 nullifier = keccak256("nullifier3");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(user);
        vm.expectRevert();
        adapter.unshieldMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_unshieldMessage_revert_replayProtection() public {
        bytes32 nullifier = keccak256("nullifier4");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(relayer);
        adapter.unshieldMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);

        // Try to replay
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                RailgunBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.unshieldMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
    }

    function test_unshieldMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        bytes32 nullifier = keccak256("nullifier5");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(relayer);
        vm.expectRevert();
        adapter.unshieldMessage(DUMMY_PROOF, inputs, DUMMY_PAYLOAD);
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
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            DUMMY_PAYLOAD,
            makeAddr("refund")
        );
    }

    function test_bridgeMessage_revert_emptyPayload() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert(RailgunBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            makeAddr("target"),
            "",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), DUMMY_PAYLOAD);
        // mockRelay.relayFee() = 0.001 ether, minMessageFee = 0
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
        bytes32 hash = adapter.shieldMessage{value: 0.01 ether}(
            DUMMY_COMMITMENT,
            DUMMY_PAYLOAD
        );
        assertTrue(adapter.isMessageVerified(hash));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes32 nullifier = keccak256("nullifier_verify");
        uint256[] memory inputs = _buildPublicInputs(
            bytes32(uint256(0xAABB)),
            nullifier,
            bytes32(uint256(0xCCDD)),
            DUMMY_PAYLOAD
        );

        vm.prank(relayer);
        bytes32 hash = adapter.unshieldMessage(
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
        adapter.shieldMessage{value: 1 ether}(DUMMY_COMMITMENT, DUMMY_PAYLOAD);

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
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
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
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(mockToken), address(0));
    }

    function test_emergencyWithdrawERC20_revert_zeroToken() public {
        vm.prank(admin);
        vm.expectRevert(RailgunBridgeAdapter.InvalidTarget.selector);
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

    function testFuzz_shieldMessage_anyValidPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.shieldMessage{value: 0.01 ether}(
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
            abi.encodeWithSelector(
                RailgunBridgeAdapter.FeeTooHigh.selector,
                fee
            )
        );
        adapter.setBridgeFee(fee);
    }
}
