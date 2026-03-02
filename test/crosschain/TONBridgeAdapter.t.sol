// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {TONBridgeAdapter, ITONBridge, ITONLightClient} from "../../contracts/crosschain/TONBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockTONBridge {
    uint256 public relayFee = 0.001 ether;
    bool public shouldSucceed = true;

    function sendMessage(
        int8,
        bytes32,
        bytes calldata
    ) external payable returns (bytes32) {
        return keccak256(abi.encodePacked(msg.sender, block.timestamp));
    }

    function verifyAndExecute(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldSucceed;
    }

    function getRelayFee() external view returns (uint256) {
        return relayFee;
    }

    function setRelayFee(uint256 _fee) external {
        relayFee = _fee;
    }

    function setShouldSucceed(bool _succeed) external {
        shouldSucceed = _succeed;
    }
}

contract MockTONLightClient {
    bool public shouldVerify = true;
    bytes32 public validatorSetHash = bytes32(uint256(0x1234));

    function verifyBlockHeader(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyStateProof(
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function currentValidatorSetHash() external view returns (bytes32) {
        return validatorSetHash;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

contract MockERC20TON is ERC20 {
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

contract TONBridgeAdapterTest is Test {
    TONBridgeAdapter public adapter;
    MockTONBridge public bridge;
    MockTONLightClient public lightClient;
    MockERC20TON public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    bytes32 constant TON_CONTRACT = bytes32(uint256(0xCAFE));
    int8 constant WORKCHAIN_0 = 0;

    function setUp() public {
        bridge = new MockTONBridge();
        lightClient = new MockTONLightClient();
        token = new MockERC20TON();

        adapter = new TONBridgeAdapter(address(bridge), admin);

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        adapter.whitelistContract(TON_CONTRACT);
        adapter.setTONLightClient(address(lightClient));
        vm.stopPrank();

        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsBridge() public view {
        assertEq(address(adapter.tonBridge()), address(bridge));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_enablesBasechain() public view {
        assertTrue(adapter.supportedWorkchains(WORKCHAIN_0));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(TONBridgeAdapter.InvalidBridge.selector);
        new TONBridgeAdapter(address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(TONBridgeAdapter.InvalidTarget.selector);
        new TONBridgeAdapter(address(bridge), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.TON_CHAIN_ID(), 16_100);
        assertEq(adapter.DEFAULT_WORKCHAIN(), 0);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.VALIDATOR_QUORUM_BPS(), 6_667);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 16_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "TON");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setTONBridge() public {
        address newBridge = address(0x999);
        vm.prank(admin);
        adapter.setTONBridge(newBridge);
        assertEq(address(adapter.tonBridge()), newBridge);
    }

    function test_setTONBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(TONBridgeAdapter.InvalidBridge.selector);
        adapter.setTONBridge(address(0));
    }

    function test_setTONBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setTONBridge(address(0x999));
    }

    function test_setTONLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setTONLightClient(newClient);
        assertEq(address(adapter.tonLightClient()), newClient);
    }

    function test_whitelistContract() public {
        bytes32 contract_ = bytes32(uint256(0xBEEF));
        vm.prank(admin);
        adapter.whitelistContract(contract_);
        assertTrue(adapter.whitelistedContracts(contract_));
    }

    function test_whitelistContract_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(TONBridgeAdapter.InvalidTarget.selector);
        adapter.whitelistContract(bytes32(0));
    }

    function test_removeContract() public {
        vm.prank(admin);
        adapter.removeContract(TON_CONTRACT);
        assertFalse(adapter.whitelistedContracts(TON_CONTRACT));
    }

    function test_setSupportedWorkchain() public {
        vm.prank(admin);
        adapter.setSupportedWorkchain(1, true);
        assertTrue(adapter.supportedWorkchains(1));
    }

    function test_setSupportedWorkchain_disable() public {
        vm.prank(admin);
        adapter.setSupportedWorkchain(WORKCHAIN_0, false);
        assertFalse(adapter.supportedWorkchains(WORKCHAIN_0));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(TONBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
              SEND MESSAGE (ZASEON → TON)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.1 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"aa"
        );
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"bb"
        );
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsUnsupportedWorkchain() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                TONBridgeAdapter.InvalidWorkchain.selector,
                int8(5)
            )
        );
        adapter.sendMessage{value: 0.1 ether}(5, TON_CONTRACT, hex"deadbeef");
    }

    function test_sendMessage_revertsZeroTarget() public {
        vm.prank(operator);
        vm.expectRevert(TONBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            bytes32(0),
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(TONBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex""
        );
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(TONBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            longPayload
        );
    }

    function test_sendMessage_revertsInsufficientFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(1 ether);

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.001 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"deadbeef"
        );
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"beef"
        );

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (TON → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );
        bytes memory proof = new bytes(64);

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            payload,
            proof
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsZeroSender() public {
        vm.prank(relayer);
        vm.expectRevert(TONBridgeAdapter.InvalidTarget.selector);
        adapter.receiveMessage(
            bytes32(0),
            WORKCHAIN_0,
            hex"deadbeef",
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsUnsupportedWorkchain() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                TONBridgeAdapter.InvalidWorkchain.selector,
                int8(5)
            )
        );
        adapter.receiveMessage(
            TON_CONTRACT,
            5,
            hex"deadbeef",
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        vm.prank(relayer);
        vm.expectRevert(TONBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            hex"",
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsShortProof() public {
        vm.prank(relayer);
        vm.expectRevert(TONBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            hex"deadbeef",
            hex"abcd"
        );
    }

    function test_receiveMessage_revertsNotWhitelisted() public {
        bytes32 unknown = bytes32(uint256(0xBAD));
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                TONBridgeAdapter.ContractNotWhitelisted.selector,
                unknown
            )
        );
        adapter.receiveMessage(
            unknown,
            WORKCHAIN_0,
            hex"deadbeef",
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsInvalidProof() public {
        lightClient.setShouldVerify(false);
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );
        vm.prank(relayer);
        vm.expectRevert(TONBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            payload,
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = bytes32(uint256(42));
        bytes memory payload = abi.encodePacked(nullifier, hex"aa");

        vm.startPrank(relayer);
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            payload,
            new bytes(64)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                TONBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            payload,
            new bytes(64)
        );
        vm.stopPrank();
    }

    function test_receiveMessage_revertsNonRelayer() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            hex"deadbeef",
            new bytes(64)
        );
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            hex"deadbeef",
            new bytes(64)
        );
    }

    /*//////////////////////////////////////////////////////////////
                      IBRIDGEADAPTER
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        address target = address(0x123);
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            target,
            hex"deadbeef",
            operator
        );
        assertTrue(id != bytes32(0));
        assertTrue(adapter.isMessageVerified(id));
    }

    function test_bridgeMessage_revertsZeroTarget() public {
        vm.prank(operator);
        vm.expectRevert(TONBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            operator
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(TONBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0x123),
            hex"",
            operator
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0x123), hex"deadbeef");
        assertEq(fee, 0.001 ether); // Mock relay fee
    }

    function test_isMessageVerified_false() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(999))));
    }

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY
    //////////////////////////////////////////////////////////////*/

    function test_pause_unpause() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());

        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_pause_revertsNonPauser() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    function test_withdrawFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            hex"beef"
        );

        uint256 fees = adapter.accumulatedFees();
        assertTrue(fees > 0);

        uint256 balBefore = admin.balance;
        vm.prank(admin);
        adapter.withdrawFees(payable(admin));
        assertEq(admin.balance, balBefore + fees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        uint256 balBefore = admin.balance;
        vm.prank(admin);
        adapter.emergencyWithdrawETH(payable(admin), 5 ether);
        assertEq(admin.balance, balBefore + 5 ether);
    }

    function test_emergencyWithdrawERC20() public {
        token.transfer(address(adapter), 100 ether);
        assertEq(token.balanceOf(address(adapter)), 100 ether);

        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(token), admin);
        assertEq(token.balanceOf(admin), 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_sendMessage(bytes calldata payload) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.1 ether}(
            WORKCHAIN_0,
            TON_CONTRACT,
            payload
        );
        assertTrue(hash != bytes32(0));
    }

    function testFuzz_bridgeFee(uint256 fee) public {
        fee = bound(fee, 0, 100);
        vm.prank(admin);
        adapter.setBridgeFee(fee);
        assertEq(adapter.bridgeFee(), fee);
    }

    function testFuzz_bridgeFee_revertsAboveMax(uint256 fee) public {
        fee = bound(fee, 101, type(uint256).max);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                TONBridgeAdapter.FeeTooHigh.selector,
                fee
            )
        );
        adapter.setBridgeFee(fee);
    }

    function testFuzz_receiveMessage_uniqueNullifiers(
        bytes32 nullifier
    ) public {
        vm.assume(nullifier != bytes32(0));
        bytes memory payload = abi.encodePacked(nullifier, hex"aabb");

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            TON_CONTRACT,
            WORKCHAIN_0,
            payload,
            new bytes(64)
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
    }
}
