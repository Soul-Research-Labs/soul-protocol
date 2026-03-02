// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SuiBridgeAdapter, ISuiBridge, ISuiLightClient} from "../../contracts/crosschain/SuiBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockSuiBridge {
    bool public shouldSucceed = true;
    uint256 public lastAmount;
    bytes32 public lastSuiAddress;

    function sendToSui(
        bytes32 suiAddress,
        uint256 amount,
        uint8
    ) external payable {
        lastSuiAddress = suiAddress;
        lastAmount = amount;
    }

    function executeMessage(
        bytes calldata,
        bytes[] calldata
    ) external {}

    function isMessageProcessed(
        uint8,
        uint64
    ) external pure returns (bool) {
        return false;
    }
}

contract MockSuiLightClient {
    bool public shouldVerify = true;
    uint64 public epoch = 100;

    function verifyCommitteeSignature(
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function currentEpoch() external view returns (uint64) {
        return epoch;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }

    function setEpoch(uint64 _epoch) external {
        epoch = _epoch;
    }
}

contract MockERC20Sui is ERC20 {
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

contract SuiBridgeAdapterTest is Test {
    SuiBridgeAdapter public adapter;
    MockSuiBridge public bridge;
    MockSuiLightClient public lightClient;
    MockERC20Sui public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    bytes32 constant SUI_PROGRAM = bytes32(uint256(0xCAFE));

    function setUp() public {
        bridge = new MockSuiBridge();
        lightClient = new MockSuiLightClient();
        token = new MockERC20Sui();

        adapter = new SuiBridgeAdapter(
            address(bridge),
            address(lightClient),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        adapter.whitelistProgram(SUI_PROGRAM);
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
        assertEq(address(adapter.suiBridge()), address(bridge));
    }

    function test_constructor_setsLightClient() public view {
        assertEq(address(adapter.suiLightClient()), address(lightClient));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(SuiBridgeAdapter.InvalidBridge.selector);
        new SuiBridgeAdapter(address(0), address(lightClient), admin);
    }

    function test_constructor_revertsZeroLightClient() public {
        vm.expectRevert(SuiBridgeAdapter.InvalidLightClient.selector);
        new SuiBridgeAdapter(address(bridge), address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(SuiBridgeAdapter.InvalidTarget.selector);
        new SuiBridgeAdapter(address(bridge), address(lightClient), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.SUI_CHAIN_ID(), 14_100);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.COMMITTEE_QUORUM_BPS(), 6_667);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 14_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Sui");
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

    function test_setSuiBridge() public {
        address newBridge = address(0x999);
        vm.prank(admin);
        adapter.setSuiBridge(newBridge);
        assertEq(address(adapter.suiBridge()), newBridge);
    }

    function test_setSuiBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(SuiBridgeAdapter.InvalidBridge.selector);
        adapter.setSuiBridge(address(0));
    }

    function test_setSuiBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setSuiBridge(address(0x999));
    }

    function test_setSuiLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setSuiLightClient(newClient);
        assertEq(address(adapter.suiLightClient()), newClient);
    }

    function test_setSuiLightClient_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(SuiBridgeAdapter.InvalidLightClient.selector);
        adapter.setSuiLightClient(address(0));
    }

    function test_whitelistProgram() public {
        bytes32 prog = bytes32(uint256(0xBEEF));
        vm.prank(admin);
        adapter.whitelistProgram(prog);
        assertTrue(adapter.whitelistedPrograms(prog));
    }

    function test_whitelistProgram_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(SuiBridgeAdapter.InvalidTarget.selector);
        adapter.whitelistProgram(bytes32(0));
    }

    function test_removeProgram() public {
        vm.prank(admin);
        adapter.removeProgram(SUI_PROGRAM);
        assertFalse(adapter.whitelistedPrograms(SUI_PROGRAM));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SuiBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
              SEND MESSAGE (ZASEON → Sui)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            SUI_PROGRAM,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, hex"aa");
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, hex"bb");
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsZeroTarget() public {
        vm.prank(operator);
        vm.expectRevert(SuiBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(SuiBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(SuiBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, longPayload);
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, hex"deadbeef");
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(SUI_PROGRAM, hex"deadbeef");
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(SUI_PROGRAM, hex"beef");

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (Sui → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );
        bytes memory proof = new bytes(64);

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(SUI_PROGRAM, payload, proof);

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsZeroSender() public {
        vm.prank(relayer);
        vm.expectRevert(SuiBridgeAdapter.InvalidTarget.selector);
        adapter.receiveMessage(bytes32(0), hex"deadbeef", new bytes(64));
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        vm.prank(relayer);
        vm.expectRevert(SuiBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(SUI_PROGRAM, hex"", new bytes(64));
    }

    function test_receiveMessage_revertsShortProof() public {
        vm.prank(relayer);
        vm.expectRevert(SuiBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(SUI_PROGRAM, hex"deadbeef", hex"abcd");
    }

    function test_receiveMessage_revertsNotWhitelisted() public {
        bytes32 unknownProgram = bytes32(uint256(0xBAD));
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SuiBridgeAdapter.ProgramNotWhitelisted.selector,
                unknownProgram
            )
        );
        adapter.receiveMessage(unknownProgram, hex"deadbeef", new bytes(64));
    }

    function test_receiveMessage_revertsInvalidProof() public {
        lightClient.setShouldVerify(false);
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );
        vm.prank(relayer);
        vm.expectRevert(SuiBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(SUI_PROGRAM, payload, new bytes(64));
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = bytes32(uint256(42));
        bytes memory payload = abi.encodePacked(nullifier, hex"aa");

        vm.startPrank(relayer);
        adapter.receiveMessage(SUI_PROGRAM, payload, new bytes(64));

        vm.expectRevert(
            abi.encodeWithSelector(
                SuiBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(SUI_PROGRAM, payload, new bytes(64));
        vm.stopPrank();
    }

    function test_receiveMessage_revertsNonRelayer() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(SUI_PROGRAM, hex"deadbeef", new bytes(64));
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(SUI_PROGRAM, hex"deadbeef", new bytes(64));
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
        vm.expectRevert(SuiBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            operator
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(SuiBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0x123),
            hex"",
            operator
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0x123), hex"deadbeef");
        assertEq(fee, 0); // minMessageFee default is 0
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
        adapter.sendMessage{value: 1 ether}(SUI_PROGRAM, hex"beef");

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
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            SUI_PROGRAM,
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
            abi.encodeWithSelector(SuiBridgeAdapter.FeeTooHigh.selector, fee)
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
            SUI_PROGRAM,
            payload,
            new bytes(64)
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
    }
}
