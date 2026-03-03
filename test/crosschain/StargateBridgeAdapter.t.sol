// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {StargateBridgeAdapter, IStargateRouter, IStargateVerifier} from "../../contracts/crosschain/StargateBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockStargateRouter {
    bytes32 public nextMessageId = keccak256("stargate-msg-1");
    bool public shouldRevert;

    function send(
        IStargateRouter.SendParam calldata,
        IStargateRouter.MessagingFee calldata,
        address
    ) external payable returns (bytes32) {
        require(!shouldRevert, "MockStargateRouter: reverted");
        return nextMessageId;
    }

    function quoteSend(
        IStargateRouter.SendParam calldata,
        bool
    ) external pure returns (IStargateRouter.MessagingFee memory) {
        return
            IStargateRouter.MessagingFee({
                nativeFee: 0.001 ether,
                lzTokenFee: 0
            });
    }

    function setNextMessageId(bytes32 _id) external {
        nextMessageId = _id;
    }

    function setShouldRevert(bool _r) external {
        shouldRevert = _r;
    }
}

contract MockStargateVerifier {
    bool public shouldVerify = true;
    bytes32 public poolHash = keccak256("stargate-pool-1");

    function verifyDelivery(
        bytes calldata,
        bytes calldata
    ) external returns (bool) {
        return shouldVerify;
    }

    function currentPoolHash() external view returns (bytes32) {
        return poolHash;
    }

    function setShouldVerify(bool _v) external {
        shouldVerify = _v;
    }
}

contract MockERC20Stargate is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract StargateBridgeAdapterTest is Test {
    StargateBridgeAdapter public adapter;
    MockStargateRouter public bridge;
    MockStargateVerifier public verifier;
    MockERC20Stargate public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);

    function setUp() public {
        bridge = new MockStargateRouter();
        verifier = new MockStargateVerifier();
        token = new MockERC20Stargate();
        adapter = new StargateBridgeAdapter(
            address(bridge),
            address(verifier),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        vm.stopPrank();

        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    function test_constructor_setsBridge() public view {
        assertEq(address(adapter.stargateRouter()), address(bridge));
    }

    function test_constructor_setsVerifier() public view {
        assertEq(address(adapter.stargateVerifier()), address(verifier));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(StargateBridgeAdapter.InvalidBridge.selector);
        new StargateBridgeAdapter(address(0), address(verifier), admin);
    }

    function test_constructor_revertsZeroVerifier() public {
        vm.expectRevert(StargateBridgeAdapter.InvalidVerifier.selector);
        new StargateBridgeAdapter(address(bridge), address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(StargateBridgeAdapter.InvalidTarget.selector);
        new StargateBridgeAdapter(
            address(bridge),
            address(verifier),
            address(0)
        );
    }

    function test_constants() public view {
        assertEq(adapter.STARGATE_PROTOCOL_ID(), 29_100);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MIN_PROOF_SIZE(), 32);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
    }

    function test_chainId() public view {
        assertEq(adapter.chainId(), 29_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Stargate");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    function test_sendMessage_success() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            keccak256("dest"),
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
    }

    function test_sendMessage_revertsZeroDestination() public {
        vm.prank(operator);
        vm.expectRevert(StargateBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(StargateBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(keccak256("dest"), hex"");
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            keccak256("dest"),
            hex"deadbeef"
        );
    }

    function test_receiveMessage_success() public {
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("pool"));
        inputs[1] = uint256(keccak256("null-1"));
        inputs[2] = uint256(keccak256("source"));
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(proof, inputs, hex"beef");
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsInvalidProof() public {
        verifier.setShouldVerify(false);
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);
        inputs[1] = uint256(keccak256("null-2"));

        vm.prank(relayer);
        vm.expectRevert(StargateBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(proof, inputs, hex"beef");
    }

    function test_receiveMessage_revertsDuplicateNullifier() public {
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);
        inputs[1] = uint256(keccak256("null-dup"));

        vm.startPrank(relayer);
        adapter.receiveMessage(proof, inputs, hex"beef");
        vm.expectRevert(
            abi.encodeWithSelector(
                StargateBridgeAdapter.NullifierAlreadyUsed.selector,
                keccak256("null-dup")
            )
        );
        adapter.receiveMessage(proof, inputs, hex"beef");
        vm.stopPrank();
    }

    function test_bridgeMessage_success() public {
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"deadbeef",
            address(0)
        );
        assertTrue(id != bytes32(0));
    }

    function test_bridgeMessage_revertsZeroTarget() public {
        vm.prank(operator);
        vm.expectRevert(StargateBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            address(0)
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0xBEEF), hex"deadbeef");
        assertEq(fee, 0);
    }

    function test_isMessageVerified() public {
        vm.prank(operator);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"deadbeef",
            address(0)
        );
        assertTrue(adapter.isMessageVerified(id));
        assertFalse(adapter.isMessageVerified(keccak256("unknown")));
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
                StargateBridgeAdapter.FeeTooHigh.selector,
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

    function test_pause_unpause() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_withdrawFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(keccak256("dest"), hex"beef");
        uint256 fees = adapter.accumulatedFees();
        assertGt(fees, 0);
        address payable recipient = payable(address(0xFEE));
        vm.prank(admin);
        adapter.withdrawFees(recipient);
        assertEq(adapter.accumulatedFees(), 0);
        assertEq(recipient.balance, fees);
    }

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable to = payable(address(0x123));
        vm.prank(admin);
        adapter.emergencyWithdrawETH(to, 2 ether);
        assertEq(to.balance, 2 ether);
    }

    function test_emergencyWithdrawERC20() public {
        token.mint(address(adapter), 100 ether);
        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(token), address(0x456));
        assertEq(token.balanceOf(address(0x456)), 100 ether);
    }

    function testFuzz_sendMessage_arbitraryPayload(
        bytes calldata payload
    ) public {
        vm.assume(payload.length > 0 && payload.length <= 10_000);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            keccak256("dest"),
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
                    StargateBridgeAdapter.FeeTooHigh.selector,
                    fee
                )
            );
            adapter.setBridgeFee(fee);
        }
    }

    function testFuzz_receiveMessage_uniqueNullifiers(
        bytes32 n1,
        bytes32 n2
    ) public {
        vm.assume(n1 != n2);
        bytes memory proof = new bytes(128);
        uint256[] memory inputs1 = new uint256[](4);
        inputs1[1] = uint256(n1);
        uint256[] memory inputs2 = new uint256[](4);
        inputs2[1] = uint256(n2);

        vm.startPrank(relayer);
        adapter.receiveMessage(proof, inputs1, hex"beef");
        adapter.receiveMessage(proof, inputs2, hex"cafe");
        vm.stopPrank();

        assertTrue(adapter.usedNullifiers(n1));
        assertTrue(adapter.usedNullifiers(n2));
        assertEq(adapter.totalMessagesReceived(), 2);
    }
}
