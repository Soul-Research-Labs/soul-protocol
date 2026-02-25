// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/PrivateProofRelayIntegration.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Mock proof verifier that returns configurable results via staticcall
contract MockRelayProofVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool val) external {
        shouldVerify = val;
    }

    // Called by _verifyInitiateProof
    function verifyInitiateProof(
        bytes32,
        bytes32,
        uint256,
        uint256,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    // Called by _verifyRefundProof
    function verifyRefundProof(
        bytes32,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock message verifier for cross-chain proof and relayer proof
contract MockMessageVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool val) external {
        shouldVerify = val;
    }

    function verifyCrossChainProof(
        bytes32,
        bytes32,
        uint256,
        uint256,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyRelayerProof(
        bytes32,
        bytes32,
        uint256,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock bridge adapter that accepts sendMessage calls
contract MockChainAdapter {
    bool public shouldSucceed = true;
    uint256 public lastDestChain;
    bytes public lastMessage;

    function setShouldSucceed(bool val) external {
        shouldSucceed = val;
    }

    function sendMessage(
        uint256 destChain,
        bytes calldata message
    ) external payable {
        if (!shouldSucceed) revert("adapter failed");
        lastDestChain = destChain;
        lastMessage = message;
    }

    receive() external payable {}
}

/// @notice Simple ERC20 for testing
contract MockRelayERC20 is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract PrivateProofRelayIntegrationTest is Test {
    PrivateProofRelayIntegration public relay;
    MockRelayProofVerifier public proofVerifier;
    MockMessageVerifier public msgVerifier;
    MockChainAdapter public adapter;
    MockRelayERC20 public token;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public relayer = makeAddr("relayer");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");

    uint256 constant THIS_CHAIN = 1;
    uint256 constant DEST_CHAIN = 42161;

    bytes32 constant COMMITMENT = keccak256("commitment1");
    bytes32 constant NULLIFIER_HASH = keccak256("nullifier1");
    bytes32 constant STEALTH_RECIPIENT = bytes32(uint256(uint160(0xBEEF)));

    // Cache NATIVE_TOKEN to avoid external call consuming vm.prank/vm.expectRevert
    address constant NATIVE =
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    function setUp() public {
        proofVerifier = new MockRelayProofVerifier();
        msgVerifier = new MockMessageVerifier();
        adapter = new MockChainAdapter();
        token = new MockRelayERC20();

        relay = new PrivateProofRelayIntegration(
            address(proofVerifier),
            address(msgVerifier),
            THIS_CHAIN
        );

        relay.grantRole(relay.OPERATOR_ROLE(), operator);
        relay.grantRole(relay.RELAYER_ROLE(), relayer);
        relay.grantRole(relay.GUARDIAN_ROLE(), guardian);

        // Configure destination chain
        vm.prank(operator);
        relay.setChainConfig(
            DEST_CHAIN,
            address(adapter),
            12,
            100 ether,
            1000 ether
        );

        // Authorize relayer
        vm.prank(operator);
        relay.setRelayerAuthorization(relayer, true);
    }

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsVerifiers() public view {
        assertEq(relay.proofVerifier(), address(proofVerifier));
        assertEq(relay.messageVerifier(), address(msgVerifier));
    }

    function test_Constructor_SetsChainId() public view {
        assertEq(relay.THIS_CHAIN_ID(), THIS_CHAIN);
    }

    function test_Constructor_GrantsRoles() public view {
        assertTrue(relay.hasRole(relay.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(relay.hasRole(relay.OPERATOR_ROLE(), admin));
        assertTrue(relay.hasRole(relay.GUARDIAN_ROLE(), admin));
    }

    function test_Constructor_RevertZeroProofVerifier() public {
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        new PrivateProofRelayIntegration(address(0), address(msgVerifier), 1);
    }

    function test_Constructor_RevertZeroMessageVerifier() public {
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        new PrivateProofRelayIntegration(address(proofVerifier), address(0), 1);
    }

    /*//////////////////////////////////////////////////////////////
                       CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_SetChainConfig_Success() public {
        vm.prank(operator);
        relay.setChainConfig(10, address(adapter), 6, 50 ether, 500 ether);

        PrivateProofRelayIntegration.ChainConfig memory config = relay
            .getChainConfig(10);
        assertTrue(config.isSupported);
        assertEq(config.chainAdapter, address(adapter));
        assertEq(config.minConfirmations, 6);
        assertEq(config.maxRelayAmount, 50 ether);
        assertEq(config.dailyLimit, 500 ether);
    }

    function test_SetChainConfig_RevertZeroAdapter() public {
        vm.prank(operator);
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        relay.setChainConfig(10, address(0), 6, 50 ether, 500 ether);
    }

    function test_SetChainConfig_RevertSameChain() public {
        vm.prank(operator);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidChainId.selector);
        relay.setChainConfig(
            THIS_CHAIN,
            address(adapter),
            6,
            50 ether,
            500 ether
        );
    }

    function test_SetChainConfig_UpdateExisting() public {
        vm.prank(operator);
        relay.setChainConfig(
            DEST_CHAIN,
            makeAddr("newAdapter"),
            24,
            200 ether,
            2000 ether
        );

        PrivateProofRelayIntegration.ChainConfig memory config = relay
            .getChainConfig(DEST_CHAIN);
        assertEq(config.chainAdapter, makeAddr("newAdapter"));
        assertEq(config.minConfirmations, 24);
    }

    function test_SetChainConfig_AddsSupportedChain() public {
        vm.prank(operator);
        relay.setChainConfig(10, address(adapter), 6, 50 ether, 500 ether);

        uint256[] memory chains = relay.getSupportedChains();
        // DEST_CHAIN + 10
        assertEq(chains.length, 2);
    }

    function test_SetRelayerAuthorization() public {
        address newRelayer = makeAddr("newRelayer");
        vm.prank(operator);
        relay.setRelayerAuthorization(newRelayer, true);
        assertTrue(relay.authorizedRelayers(newRelayer));

        vm.prank(operator);
        relay.setRelayerAuthorization(newRelayer, false);
        assertFalse(relay.authorizedRelayers(newRelayer));
    }

    function test_SetRelayerAuthorization_RevertZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        relay.setRelayerAuthorization(address(0), true);
    }

    /*//////////////////////////////////////////////////////////////
                   INITIATE PRIVATE RELAY
    //////////////////////////////////////////////////////////////*/

    function _buildMessage()
        internal
        pure
        returns (PrivateProofRelayIntegration.PrivateRelayMessage memory)
    {
        return
            PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: THIS_CHAIN,
                destChain: DEST_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });
    }

    function test_InitiatePrivateRelay_Success() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);

        // Check transfer recorded
        bytes32[] memory userRequests = relay.getUserRequests(user1);
        assertEq(userRequests.length, 1);

        // Check nullifier marked
        assertTrue(relay.isLocalNullifierUsed(NULLIFIER_HASH));
    }

    function test_InitiatePrivateRelay_RevertZeroCommitment() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        msg_.commitment = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidCommitment.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertZeroNullifier() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        msg_.nullifierHash = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidNullifier.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertZeroRecipient() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        msg_.destRecipient = bytes32(0);

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidRecipient.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertWrongSourceChain() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        msg_.sourceChain = 999;

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidChainId.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertUnsupportedChain() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        msg_.destChain = 999; // Not configured

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.ChainNotSupported.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertNullifierAlreadyUsed() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();

        vm.deal(user1, 2 ether);
        vm.prank(user1);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);

        // Same nullifier again
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.NullifierAlreadyUsed.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertInvalidProof() public {
        proofVerifier.setShouldVerify(false);

        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidProof.selector);
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_RevertWhenPaused() public {
        vm.prank(guardian);
        relay.pause();

        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert();
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    function test_InitiatePrivateRelay_EmitsEvent() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectEmit(false, true, false, false);
        emit PrivateProofRelayIntegration.PrivateRelayInitiated(
            bytes32(0),
            COMMITMENT,
            THIS_CHAIN,
            DEST_CHAIN,
            block.timestamp
        );
        relay.initiatePrivateRelay{value: 0.1 ether}(msg_);
    }

    /*//////////////////////////////////////////////////////////////
                  COMPLETE PRIVATE RELAY
    //////////////////////////////////////////////////////////////*/

    function test_CompletePrivateRelay_Success() public {
        // Build message for destination chain
        PrivateProofRelayIntegration.PrivateRelayMessage memory msg_ = PrivateProofRelayIntegration
            .PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN, // Source is the OTHER chain
                destChain: THIS_CHAIN, // Dest is THIS chain
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");

        // Check cross-chain nullifier registered
        assertTrue(relay.crossChainNullifiers(NULLIFIER_HASH, DEST_CHAIN));
    }

    function test_CompletePrivateRelay_RevertUnauthorizedRelayer() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(user1); // Not authorized
        vm.expectRevert(PrivateProofRelayIntegration.UnauthorizedRelayer.selector);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateRelay_RevertWrongDestChain() public {
        PrivateProofRelayIntegration.PrivateRelayMessage memory msg_ = PrivateProofRelayIntegration
            .PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: 999, // Wrong
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        vm.expectRevert(PrivateProofRelayIntegration.InvalidChainId.selector);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateRelay_RevertNullifierAlreadyUsed() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");

        // Same nullifier again
        vm.prank(relayer);
        vm.expectRevert(PrivateProofRelayIntegration.NullifierAlreadyUsed.selector);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");
    }

    function test_CompletePrivateRelay_RevertCrossChainVerificationFailed()
        public
    {
        msgVerifier.setShouldVerify(false);

        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        vm.expectRevert(
            PrivateProofRelayIntegration.CrossChainVerificationFailed.selector
        );
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN NULLIFIER VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_VerifyCrossChainNullifier_Unused() public view {
        assertTrue(
            relay.verifyCrossChainNullifier(NULLIFIER_HASH, DEST_CHAIN)
        );
    }

    function test_VerifyCrossChainNullifier_Used() public {
        // Complete a transfer to mark it
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: NULLIFIER_HASH,
                sourceChain: DEST_CHAIN,
                destChain: THIS_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.prank(relayer);
        relay.completePrivateRelay(msg_, hex"aabb", hex"ccdd");

        assertFalse(
            relay.verifyCrossChainNullifier(NULLIFIER_HASH, DEST_CHAIN)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       REFUND MECHANISM
    //////////////////////////////////////////////////////////////*/

    function test_RefundExpiredRelay_Success() public {
        // Initiate relay
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        relay.initiatePrivateRelay{value: 0.5 ether}(msg_);

        bytes32[] memory transfers_ = relay.getUserRequests(user1);
        bytes32 requestId = transfers_[0];

        // Fund the relay contract for the refund (initiate forwards ETH to adapter)
        vm.deal(address(relay), 0.5 ether);

        // Warp past expiry
        vm.warp(block.timestamp + relay.REQUEST_EXPIRY() + 1);

        // Build refund proof: first 20 bytes = refund recipient address
        bytes memory refundProof = abi.encodePacked(
            user1,
            hex"aabbccddee1122334455"
        );

        uint256 balBefore = user1.balance;
        relay.refundExpiredRelay(requestId, refundProof);

        assertEq(user1.balance, balBefore + 0.5 ether);
    }

    function test_RefundExpiredRelay_RevertNotExpired() public {
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = _buildMessage();
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        relay.initiatePrivateRelay{value: 0.5 ether}(msg_);

        bytes32[] memory transfers_ = relay.getUserRequests(user1);
        bytes32 requestId = transfers_[0];

        // Don't warp — not expired yet
        vm.expectRevert(PrivateProofRelayIntegration.RequestNotFound.selector);
        relay.refundExpiredRelay(requestId, hex"");
    }

    function test_RefundExpiredRelay_RevertNotFound() public {
        vm.expectRevert(PrivateProofRelayIntegration.RequestNotFound.selector);
        relay.refundExpiredRelay(keccak256("fake"), hex"");
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetChainConfig() public view {
        PrivateProofRelayIntegration.ChainConfig memory config = relay
            .getChainConfig(DEST_CHAIN);
        assertTrue(config.isSupported);
        assertEq(config.chainAdapter, address(adapter));
    }

    function test_IsChainSupported() public view {
        assertTrue(relay.isChainSupported(DEST_CHAIN));
        assertFalse(relay.isChainSupported(999));
    }

    function test_GetSupportedChains() public view {
        uint256[] memory chains = relay.getSupportedChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], DEST_CHAIN);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetProofVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        relay.setProofVerifier(newVerifier);
        assertEq(relay.proofVerifier(), newVerifier);
    }

    function test_SetProofVerifier_RevertZeroAddress() public {
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        relay.setProofVerifier(address(0));
    }

    function test_SetMessageVerifier() public {
        address newVerifier = makeAddr("newMsgVerifier");
        relay.setMessageVerifier(newVerifier);
        assertEq(relay.messageVerifier(), newVerifier);
    }

    function test_SetMessageVerifier_RevertZeroAddress() public {
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        relay.setMessageVerifier(address(0));
    }

    function test_PauseUnpause() public {
        vm.prank(guardian);
        relay.pause();
        assertTrue(relay.paused());

        vm.prank(operator);
        relay.unpause();
        assertFalse(relay.paused());
    }

    function test_EmergencyWithdraw_Native() public {
        // Fund the relay contract
        vm.deal(address(relay), 5 ether);

        address recipient = makeAddr("recipient");
        relay.emergencyWithdraw(NATIVE, recipient);
        assertEq(recipient.balance, 5 ether);
    }

    function test_EmergencyWithdraw_ERC20() public {
        token.transfer(address(relay), 1000 ether);

        address recipient = makeAddr("recipient");
        relay.emergencyWithdraw(address(token), recipient);
        assertEq(token.balanceOf(recipient), 1000 ether);
    }

    function test_EmergencyWithdraw_RevertZeroAddress() public {
        vm.expectRevert(PrivateProofRelayIntegration.ZeroAddress.selector);
        relay.emergencyWithdraw(NATIVE, address(0));
    }

    function test_ReceiveETH() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        (bool ok, ) = address(relay).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(relay).balance, 0.5 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetChainConfig_UniqueChains(uint256 chainId) public {
        vm.assume(
            chainId != THIS_CHAIN && chainId != DEST_CHAIN && chainId != 0
        );
        vm.prank(operator);
        relay.setChainConfig(
            chainId,
            address(adapter),
            6,
            50 ether,
            500 ether
        );
        assertTrue(relay.isChainSupported(chainId));
    }

    function testFuzz_InitiateTransfer_UniqueNullifiers(
        bytes32 nullifier
    ) public {
        vm.assume(nullifier != bytes32(0));
        PrivateProofRelayIntegration.PrivateRelayMessage
            memory msg_ = PrivateProofRelayIntegration.PrivateRelayMessage({
                commitment: COMMITMENT,
                nullifierHash: nullifier,
                sourceChain: THIS_CHAIN,
                destChain: DEST_CHAIN,
                destRecipient: STEALTH_RECIPIENT,
                proof: hex"aabbccdd"
            });

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        relay.initiatePrivateRelay{value: 0.01 ether}(msg_);

        assertTrue(relay.isLocalNullifierUsed(nullifier));
    }
}
