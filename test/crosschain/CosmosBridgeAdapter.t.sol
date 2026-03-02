// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CosmosBridgeAdapter, IGravityBridge, IIBCLightClient} from "../../contracts/crosschain/CosmosBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockGravityBridge {
    bytes32 public nextTransferId = keccak256("gravity-transfer-1");
    uint256 public relayFee = 0.001 ether;
    uint256 public valsetNonce = 42;
    bytes32 public valsetCheckpoint = keccak256("valset-checkpoint-42");
    bool public shouldRevert;

    function sendToCosmos(
        bytes calldata,
        uint256,
        address
    ) external payable returns (bytes32) {
        require(!shouldRevert, "MockGravityBridge: reverted");
        return nextTransferId;
    }

    function estimateRelayFee() external view returns (uint256) {
        return relayFee;
    }

    function state_lastValsetNonce() external view returns (uint256) {
        return valsetNonce;
    }

    function state_lastValsetCheckpoint() external view returns (bytes32) {
        return valsetCheckpoint;
    }

    // Test helpers
    function setNextTransferId(bytes32 _id) external {
        nextTransferId = _id;
    }

    function setRelayFee(uint256 _fee) external {
        relayFee = _fee;
    }

    function setValsetNonce(uint256 _nonce) external {
        valsetNonce = _nonce;
    }

    function setValsetCheckpoint(bytes32 _cp) external {
        valsetCheckpoint = _cp;
    }

    function setShouldRevert(bool _revert) external {
        shouldRevert = _revert;
    }
}

contract MockIBCLightClient {
    bool public shouldVerify = true;
    uint64 public currentHeight = 100;

    function verifyIBCProof(bytes calldata, bytes calldata) external returns (bool) {
        return shouldVerify;
    }

    function latestHeight() external view returns (uint64) {
        return currentHeight;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }

    function setLatestHeight(uint64 _height) external {
        currentHeight = _height;
    }
}

contract MockERC20Cosmos is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/*//////////////////////////////////////////////////////////////
                        TEST CONTRACT
//////////////////////////////////////////////////////////////*/

contract CosmosBridgeAdapterTest is Test {
    CosmosBridgeAdapter public adapter;
    MockGravityBridge public gravity;
    MockIBCLightClient public ibcClient;
    MockERC20Cosmos public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    bytes32 public constant DEFAULT_IBC_CHANNEL = keccak256("channel-0");

    function setUp() public {
        gravity = new MockGravityBridge();
        ibcClient = new MockIBCLightClient();
        token = new MockERC20Cosmos();

        adapter = new CosmosBridgeAdapter(
            address(gravity),
            address(ibcClient),
            admin
        );

        // Grant roles
        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        vm.stopPrank();

        // Fund accounts
        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsGravityBridge() public view {
        assertEq(address(adapter.gravityBridge()), address(gravity));
    }

    function test_constructor_setsIBCLightClient() public view {
        assertEq(address(adapter.ibcLightClient()), address(ibcClient));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_registersDefaultChannel() public view {
        assertTrue(adapter.registeredChannels(DEFAULT_IBC_CHANNEL));
    }

    function test_constructor_revertsZeroGravity() public {
        vm.expectRevert(CosmosBridgeAdapter.InvalidGravityBridge.selector);
        new CosmosBridgeAdapter(address(0), address(ibcClient), admin);
    }

    function test_constructor_revertsZeroLightClient() public {
        vm.expectRevert(CosmosBridgeAdapter.InvalidLightClient.selector);
        new CosmosBridgeAdapter(address(gravity), address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        new CosmosBridgeAdapter(address(gravity), address(ibcClient), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.COSMOS_CHAIN_ID(), 7100);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MIN_PROOF_SIZE(), 64);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 7100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Cosmos");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    function test_getValsetCheckpoint() public view {
        assertEq(
            adapter.getValsetCheckpoint(),
            keccak256("valset-checkpoint-42")
        );
    }

    function test_getValsetNonce() public view {
        assertEq(adapter.getValsetNonce(), 42);
    }

    function test_getLatestIBCHeight() public view {
        assertEq(adapter.getLatestIBCHeight(), 100);
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setGravityBridge() public {
        address newGravity = address(0x999);
        vm.prank(admin);
        adapter.setGravityBridge(newGravity);
        assertEq(address(adapter.gravityBridge()), newGravity);
    }

    function test_setGravityBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidGravityBridge.selector);
        adapter.setGravityBridge(address(0));
    }

    function test_setGravityBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setGravityBridge(address(0x999));
    }

    function test_setIBCLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setIBCLightClient(newClient);
        assertEq(address(adapter.ibcLightClient()), newClient);
    }

    function test_setIBCLightClient_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidLightClient.selector);
        adapter.setIBCLightClient(address(0));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(CosmosBridgeAdapter.FeeTooHigh.selector, 101));
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    function test_setDefaultCosmosDestination() public {
        bytes memory dest = bytes("cosmos1abc123");
        vm.prank(admin);
        adapter.setDefaultCosmosDestination(dest);
        assertEq(adapter.defaultCosmosDestination(), dest);
    }

    function test_setDefaultCosmosDestination_revertsEmpty() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.setDefaultCosmosDestination(bytes(""));
    }

    function test_registerIBCChannel() public {
        bytes32 channel = keccak256("channel-42");
        vm.prank(admin);
        adapter.registerIBCChannel(channel);
        assertTrue(adapter.registeredChannels(channel));
    }

    function test_deregisterIBCChannel() public {
        bytes32 channel = keccak256("channel-42");
        vm.startPrank(admin);
        adapter.registerIBCChannel(channel);
        adapter.deregisterIBCChannel(channel);
        vm.stopPrank();
        assertFalse(adapter.registeredChannels(channel));
    }

    /*//////////////////////////////////////////////////////////////
                   SEND MESSAGE (ZASEON → COSMOS)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        bytes memory dest = bytes("cosmos1abc123");
        bytes memory payload = hex"deadbeef";

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(dest, payload);

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        bytes memory dest = bytes("cosmos1abc123");
        bytes memory payload = hex"deadbeef";

        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(dest, payload);
        adapter.sendMessage{value: 0.01 ether}(dest, payload);
        vm.stopPrank();

        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_calculatesProtocolFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        bytes memory dest = bytes("cosmos1abc123");
        bytes memory payload = hex"deadbeef";

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(dest, payload);

        // 50/10000 * 1 ether = 0.005 ether
        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    function test_sendMessage_revertsEmptyDestination() public {
        vm.prank(operator);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes(""), hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(CosmosBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes("cosmos1abc"), hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(CosmosBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(
            bytes("cosmos1abc"),
            longPayload
        );
    }

    function test_sendMessage_revertsInsufficientFee() public {
        gravity.setRelayFee(1 ether);
        vm.prank(admin);
        adapter.setMinMessageFee(0.5 ether);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                CosmosBridgeAdapter.InsufficientFee.selector,
                1.5 ether,
                0.1 ether
            )
        );
        adapter.sendMessage{value: 0.1 ether}(
            bytes("cosmos1abc"),
            hex"beef"
        );
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            bytes("cosmos1abc"),
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            bytes("cosmos1abc"),
            hex"deadbeef"
        );
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (COSMOS → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("nullifier-1");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("consensus-state"));
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs[3] = uint256(keccak256(hex"deadbeef"));

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(proof, inputs, hex"deadbeef");

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function test_receiveMessage_revertsInvalidProof() public {
        ibcClient.setShouldVerify(false);
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("cs"));
        inputs[1] = uint256(keccak256("null"));
        inputs[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.prank(relayer);
        vm.expectRevert(CosmosBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(proof, inputs, hex"beef");
    }

    function test_receiveMessage_revertsInvalidChannel() public {
        bytes memory proof = new bytes(128);
        bytes32 unregisteredChannel = keccak256("channel-999");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("cs"));
        inputs[1] = uint256(keccak256("null"));
        inputs[2] = uint256(unregisteredChannel);
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.prank(relayer);
        vm.expectRevert(CosmosBridgeAdapter.InvalidChannel.selector);
        adapter.receiveMessage(proof, inputs, hex"beef");
    }

    function test_receiveMessage_revertsDuplicateNullifier() public {
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("nullifier-dup");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("cs"));
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.startPrank(relayer);
        adapter.receiveMessage(proof, inputs, hex"beef");

        vm.expectRevert(
            abi.encodeWithSelector(
                CosmosBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(proof, inputs, hex"beef");
        vm.stopPrank();
    }

    function test_receiveMessage_revertsNonRelayer() public {
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(proof, inputs, hex"beef");
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter INTERFACE
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"deadbeef",
            address(0)
        );
        assertTrue(id != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_bridgeMessage_revertsZeroTarget() public {
        vm.prank(operator);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            address(0)
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(CosmosBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"",
            address(0)
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0xBEEF), hex"deadbeef");
        assertEq(fee, 0.001 ether); // MockGravityBridge relayFee + 0 minMessageFee
    }

    function test_estimateFee_includesMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.005 ether);
        uint256 fee = adapter.estimateFee(address(0xBEEF), hex"deadbeef");
        assertEq(fee, 0.006 ether);
    }

    function test_isMessageVerified_sentMessage() public {
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"deadbeef",
            address(0)
        );
        assertTrue(adapter.isMessageVerified(id));
    }

    function test_isMessageVerified_deliveredMessage() public {
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("null-verified");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("cs"));
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.prank(relayer);
        bytes32 id = adapter.receiveMessage(proof, inputs, hex"beef");
        assertTrue(adapter.isMessageVerified(id));
    }

    function test_isMessageVerified_unknownMessage() public view {
        assertFalse(adapter.isMessageVerified(keccak256("unknown")));
    }

    function test_implementsIBridgeAdapter() public view {
        // Verify the contract satisfies IBridgeAdapter
        IBridgeAdapter iBridge = IBridgeAdapter(address(adapter));
        assertEq(address(iBridge), address(adapter));
    }

    /*//////////////////////////////////////////////////////////////
                      PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_pause_byPauser() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause_byAdmin() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_pause_revertsNonPauser() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    function test_sendMessage_revertsWhenPaused2() public {
        vm.prank(admin);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"deadbeef",
            address(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEES
    //////////////////////////////////////////////////////////////*/

    function test_withdrawFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            bytes("cosmos1abc"),
            hex"deadbeef"
        );

        uint256 fees = adapter.accumulatedFees();
        assertGt(fees, 0);

        address payable recipient = payable(address(0xFEE));
        vm.prank(admin);
        adapter.withdrawFees(recipient);

        assertEq(adapter.accumulatedFees(), 0);
        assertEq(recipient.balance, fees);
    }

    function test_withdrawFees_revertsZeroRecipient() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.withdrawFees(payable(address(0)));
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable to = payable(address(0x123));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(to, 2 ether);
        assertEq(to.balance, 2 ether);
    }

    function test_emergencyWithdrawETH_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawERC20() public {
        token.mint(address(adapter), 100 ether);
        address to = address(0x456);

        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(token), to);
        assertEq(token.balanceOf(to), 100 ether);
    }

    function test_emergencyWithdrawERC20_revertsZeroToken() public {
        vm.prank(admin);
        vm.expectRevert(CosmosBridgeAdapter.InvalidTarget.selector);
        adapter.emergencyWithdrawERC20(address(0), address(0x456));
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    function test_receiveETH() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                         ROLE CHECKS
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

    function testFuzz_sendMessage_arbitraryPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            bytes("cosmos1abc"),
            payload
        );
        assertTrue(hash != bytes32(0));
    }

    function testFuzz_setBridgeFee_bounds(uint256 fee) public {
        if (fee <= 100) {
            vm.prank(admin);
            adapter.setBridgeFee(fee);
            assertEq(adapter.bridgeFee(), fee);
        } else {
            vm.prank(admin);
            vm.expectRevert(
                abi.encodeWithSelector(
                    CosmosBridgeAdapter.FeeTooHigh.selector,
                    fee
                )
            );
            adapter.setBridgeFee(fee);
        }
    }

    function testFuzz_receiveMessage_uniqueNullifiers(
        bytes32 nullifier1,
        bytes32 nullifier2
    ) public {
        vm.assume(nullifier1 != nullifier2);

        bytes memory proof = new bytes(128);
        uint256[] memory inputs1 = new uint256[](4);
        inputs1[0] = uint256(keccak256("cs"));
        inputs1[1] = uint256(nullifier1);
        inputs1[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs1[3] = uint256(keccak256(hex"beef"));

        uint256[] memory inputs2 = new uint256[](4);
        inputs2[0] = uint256(keccak256("cs"));
        inputs2[1] = uint256(nullifier2);
        inputs2[2] = uint256(DEFAULT_IBC_CHANNEL);
        inputs2[3] = uint256(keccak256(hex"cafe"));

        vm.startPrank(relayer);
        adapter.receiveMessage(proof, inputs1, hex"beef");
        adapter.receiveMessage(proof, inputs2, hex"cafe");
        vm.stopPrank();

        assertTrue(adapter.usedNullifiers(nullifier1));
        assertTrue(adapter.usedNullifiers(nullifier2));
        assertEq(adapter.totalMessagesReceived(), 2);
    }

    function testFuzz_setMinMessageFee(uint256 fee) public {
        vm.prank(admin);
        adapter.setMinMessageFee(fee);
        assertEq(adapter.minMessageFee(), fee);
    }
}
