// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WormholeBridgeAdapter} from "../../contracts/crosschain/WormholeBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockWormholeCore {
    uint256 public messageFee_ = 0.001 ether;
    uint32 public guardianSetIndex = 1;
    uint64 public sequence;

    function publishMessage(
        uint32,
        bytes calldata,
        uint8
    ) external payable returns (uint64 seq) {
        seq = sequence++;
    }

    function messageFee() external view returns (uint256) {
        return messageFee_;
    }

    function getCurrentGuardianSetIndex() external view returns (uint32) {
        return guardianSetIndex;
    }

    function setMessageFee(uint256 _fee) external {
        messageFee_ = _fee;
    }
}

contract MockERC20Wormhole is ERC20 {
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

contract WormholeBridgeAdapterTest is Test {
    WormholeBridgeAdapter public adapter;
    MockWormholeCore public wormholeCore;
    MockERC20Wormhole public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    uint16 constant WORMHOLE_ETH_CHAIN = 2;
    bytes32 constant EMITTER = bytes32(uint256(0xCAFE));

    function setUp() public {
        wormholeCore = new MockWormholeCore();
        token = new MockERC20Wormhole();

        adapter = new WormholeBridgeAdapter(address(wormholeCore), admin);

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        // Register an emitter for Ethereum Wormhole chain
        adapter.registerEmitter(WORMHOLE_ETH_CHAIN, EMITTER);
        adapter.setSupportedChain(WORMHOLE_ETH_CHAIN, true);
        vm.stopPrank();

        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsWormholeCore() public view {
        assertEq(address(adapter.wormholeCore()), address(wormholeCore));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroCore() public {
        vm.expectRevert(WormholeBridgeAdapter.InvalidCoreBridge.selector);
        new WormholeBridgeAdapter(address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(WormholeBridgeAdapter.InvalidTarget.selector);
        new WormholeBridgeAdapter(address(wormholeCore), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.WORMHOLE_CHAIN_ID(), 13_100);
        assertEq(adapter.WORMHOLE_ETH_CHAIN_ID(), 2);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.GUARDIAN_THRESHOLD(), 13);
        assertEq(adapter.CONSISTENCY_LEVEL_FINALIZED(), 200);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 13_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Wormhole");
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

    function test_setWormholeCore() public {
        address newCore = address(0x999);
        vm.prank(admin);
        adapter.setWormholeCore(newCore);
        assertEq(address(adapter.wormholeCore()), newCore);
    }

    function test_setWormholeCore_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(WormholeBridgeAdapter.InvalidCoreBridge.selector);
        adapter.setWormholeCore(address(0));
    }

    function test_setWormholeCore_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setWormholeCore(address(0x999));
    }

    function test_registerEmitter() public {
        bytes32 newEmitter = bytes32(uint256(0xBEEF));
        vm.prank(admin);
        adapter.registerEmitter(3, newEmitter);
        assertEq(adapter.registeredEmitters(3), newEmitter);
    }

    function test_registerEmitter_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(WormholeBridgeAdapter.InvalidTarget.selector);
        adapter.registerEmitter(3, bytes32(0));
    }

    function test_removeEmitter() public {
        vm.prank(admin);
        adapter.removeEmitter(WORMHOLE_ETH_CHAIN);
        assertEq(adapter.registeredEmitters(WORMHOLE_ETH_CHAIN), bytes32(0));
    }

    function test_setSupportedChain() public {
        vm.prank(admin);
        adapter.setSupportedChain(5, true);
        assertTrue(adapter.supportedChains(5));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                WormholeBridgeAdapter.FeeTooHigh.selector,
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
                      SEND MESSAGE
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            WORMHOLE_ETH_CHAIN,
            hex"deadbeef",
            1
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(WORMHOLE_ETH_CHAIN, hex"aa", 1);
        adapter.sendMessage{value: 0.01 ether}(WORMHOLE_ETH_CHAIN, hex"bb", 1);
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsUnsupportedChain() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                WormholeBridgeAdapter.ChainNotSupported.selector,
                99
            )
        );
        adapter.sendMessage{value: 0.01 ether}(99, hex"deadbeef", 1);
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(WormholeBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(WORMHOLE_ETH_CHAIN, hex"", 1);
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(WormholeBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(WORMHOLE_ETH_CHAIN, longPayload, 1);
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            WORMHOLE_ETH_CHAIN,
            hex"deadbeef",
            1
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            WORMHOLE_ETH_CHAIN,
            hex"deadbeef",
            1
        );
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(WORMHOLE_ETH_CHAIN, hex"beef", 1);

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
                      RECEIVE MESSAGE
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 vaaHash = keccak256("test_vaa");
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            vaaHash,
            WORMHOLE_ETH_CHAIN,
            EMITTER,
            payload
        );

        assertTrue(hash != bytes32(0));
        assertTrue(adapter.verifiedVAAs(vaaHash));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsReplayedVAA() public {
        bytes32 vaaHash = keccak256("test_vaa");
        bytes memory payload1 = abi.encodePacked(bytes32(uint256(1)), hex"aa");
        bytes memory payload2 = abi.encodePacked(bytes32(uint256(2)), hex"bb");

        vm.startPrank(relayer);
        adapter.receiveMessage(vaaHash, WORMHOLE_ETH_CHAIN, EMITTER, payload1);

        vm.expectRevert(
            abi.encodeWithSelector(
                WormholeBridgeAdapter.VAAAlreadyProcessed.selector,
                vaaHash
            )
        );
        adapter.receiveMessage(vaaHash, WORMHOLE_ETH_CHAIN, EMITTER, payload2);
        vm.stopPrank();
    }

    function test_receiveMessage_revertsUnregisteredEmitter() public {
        bytes32 vaaHash = keccak256("test_vaa2");
        bytes32 wrongEmitter = bytes32(uint256(0xBAD));
        uint16 unknownChain = 99;
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                WormholeBridgeAdapter.EmitterNotRegistered.selector,
                unknownChain
            )
        );
        adapter.receiveMessage(
            vaaHash,
            unknownChain,
            wrongEmitter,
            payload
        );
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        bytes32 vaaHash = keccak256("test_vaa3");
        vm.prank(relayer);
        vm.expectRevert(WormholeBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(vaaHash, WORMHOLE_ETH_CHAIN, EMITTER, hex"");
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = bytes32(uint256(42));
        bytes memory payload = abi.encodePacked(nullifier, hex"aa");

        vm.startPrank(relayer);
        bytes32 vaaHash1 = keccak256("vaa1");
        adapter.receiveMessage(vaaHash1, WORMHOLE_ETH_CHAIN, EMITTER, payload);

        bytes32 vaaHash2 = keccak256("vaa2");
        vm.expectRevert(
            abi.encodeWithSelector(
                WormholeBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(vaaHash2, WORMHOLE_ETH_CHAIN, EMITTER, payload);
        vm.stopPrank();
    }

    function test_receiveMessage_revertsNonRelayer() public {
        bytes32 vaaHash = keccak256("test_vaa4");
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(
            vaaHash,
            WORMHOLE_ETH_CHAIN,
            EMITTER,
            hex"deadbeef"
        );
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        bytes32 vaaHash = keccak256("test_vaa5");
        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(
            vaaHash,
            WORMHOLE_ETH_CHAIN,
            EMITTER,
            hex"deadbeef"
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
        vm.expectRevert(WormholeBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            operator
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(WormholeBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0x123),
            hex"",
            operator
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0x123), hex"deadbeef");
        assertEq(fee, 0.001 ether); // Mock wormhole core messageFee
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
        // Accumulate some fees
        vm.prank(admin);
        adapter.setBridgeFee(50);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(WORMHOLE_ETH_CHAIN, hex"beef", 1);

        uint256 fees = adapter.accumulatedFees();
        assertTrue(fees > 0);

        uint256 balBefore = admin.balance;
        vm.prank(admin);
        adapter.withdrawFees(payable(admin));
        assertEq(admin.balance, balBefore + fees);
        assertEq(adapter.accumulatedFees(), 0);
    }

    function test_emergencyWithdrawETH() public {
        // Send ETH to adapter
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

    function testFuzz_sendMessage(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            WORMHOLE_ETH_CHAIN,
            payload,
            1
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
                WormholeBridgeAdapter.FeeTooHigh.selector,
                fee
            )
        );
        adapter.setBridgeFee(fee);
    }

    function testFuzz_receiveMessage_uniqueVAA(bytes32 vaaHash) public {
        vm.assume(vaaHash != bytes32(0));
        bytes memory payload = abi.encodePacked(vaaHash, hex"aabb");

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            vaaHash,
            WORMHOLE_ETH_CHAIN,
            EMITTER,
            payload
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.verifiedVAAs(vaaHash));
    }
}
