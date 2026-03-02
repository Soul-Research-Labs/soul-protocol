// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AvalancheBridgeAdapter, IAvalancheBridge, IAvalancheWarpVerifier} from "../../contracts/crosschain/AvalancheBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockAvalancheBridge {
    bytes32 public nextMessageId = keccak256("avax-msg-1");
    uint256 public relayFee = 0.001 ether;
    uint256 public verifiedHeight = 50_000_000;
    bool public shouldRevert;

    function relayMessage(
        bytes32,
        bytes calldata
    ) external payable returns (bytes32) {
        require(!shouldRevert, "MockAvalancheBridge: reverted");
        return nextMessageId;
    }

    function estimateRelayFee() external view returns (uint256) {
        return relayFee;
    }

    function latestVerifiedHeight() external view returns (uint256) {
        return verifiedHeight;
    }

    function setNextMessageId(bytes32 _id) external {
        nextMessageId = _id;
    }

    function setRelayFee(uint256 _fee) external {
        relayFee = _fee;
    }

    function setVerifiedHeight(uint256 _height) external {
        verifiedHeight = _height;
    }

    function setShouldRevert(bool _revert) external {
        shouldRevert = _revert;
    }
}

contract MockAvalancheWarpVerifier {
    bool public shouldVerify = true;
    bytes32 public validatorSetHash = keccak256("avax-valset-1");

    function verifyWarpMessage(
        bytes calldata,
        bytes calldata
    ) external returns (bool) {
        return shouldVerify;
    }

    function currentValidatorSetHash() external view returns (bytes32) {
        return validatorSetHash;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }

    function setValidatorSetHash(bytes32 _hash) external {
        validatorSetHash = _hash;
    }
}

contract MockERC20Avalanche is ERC20 {
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

contract AvalancheBridgeAdapterTest is Test {
    AvalancheBridgeAdapter public adapter;
    MockAvalancheBridge public bridge;
    MockAvalancheWarpVerifier public warpVerifier;
    MockERC20Avalanche public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    function setUp() public {
        bridge = new MockAvalancheBridge();
        warpVerifier = new MockAvalancheWarpVerifier();
        token = new MockERC20Avalanche();

        adapter = new AvalancheBridgeAdapter(
            address(bridge),
            address(warpVerifier),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
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
        assertEq(address(adapter.avalancheBridge()), address(bridge));
    }

    function test_constructor_setsVerifier() public view {
        assertEq(address(adapter.warpVerifier()), address(warpVerifier));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(AvalancheBridgeAdapter.InvalidBridge.selector);
        new AvalancheBridgeAdapter(address(0), address(warpVerifier), admin);
    }

    function test_constructor_revertsZeroVerifier() public {
        vm.expectRevert(AvalancheBridgeAdapter.InvalidVerifier.selector);
        new AvalancheBridgeAdapter(address(bridge), address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(AvalancheBridgeAdapter.InvalidTarget.selector);
        new AvalancheBridgeAdapter(
            address(bridge),
            address(warpVerifier),
            address(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.AVALANCHE_CHAIN_ID(), 11_100);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MIN_PROOF_SIZE(), 48);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 11_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Avalanche");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    function test_getCurrentValidatorSetHash() public view {
        assertEq(
            adapter.getCurrentValidatorSetHash(),
            keccak256("avax-valset-1")
        );
    }

    function test_getLatestVerifiedHeight() public view {
        assertEq(adapter.getLatestVerifiedHeight(), 50_000_000);
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setAvalancheBridge() public {
        address newBridge = address(0x999);
        vm.prank(admin);
        adapter.setAvalancheBridge(newBridge);
        assertEq(address(adapter.avalancheBridge()), newBridge);
    }

    function test_setAvalancheBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidBridge.selector);
        adapter.setAvalancheBridge(address(0));
    }

    function test_setAvalancheBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setAvalancheBridge(address(0x999));
    }

    function test_setWarpVerifier() public {
        address newVerifier = address(0x888);
        vm.prank(admin);
        adapter.setWarpVerifier(newVerifier);
        assertEq(address(adapter.warpVerifier()), newVerifier);
    }

    function test_setWarpVerifier_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidVerifier.selector);
        adapter.setWarpVerifier(address(0));
    }

    function test_registerValidatorSet() public {
        bytes32 vs = keccak256("test-valset");
        vm.prank(admin);
        adapter.registerValidatorSet(vs);
        assertTrue(adapter.verifiedValidatorSets(vs));
    }

    function test_registerValidatorSet_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidValidatorSet.selector);
        adapter.registerValidatorSet(bytes32(0));
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
                AvalancheBridgeAdapter.FeeTooHigh.selector,
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
               SEND MESSAGE (ZASEON → AVALANCHE)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        bytes32 destChain = keccak256("c-chain");
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            destChain,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        bytes32 destChain = keccak256("c-chain");
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(destChain, hex"aa");
        adapter.sendMessage{value: 0.01 ether}(destChain, hex"bb");
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsZeroDestination() public {
        vm.prank(operator);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(keccak256("chain"), hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(keccak256("chain"), longPayload);
    }

    function test_sendMessage_revertsInsufficientFee() public {
        bridge.setRelayFee(1 ether);
        vm.prank(admin);
        adapter.setMinMessageFee(0.5 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                AvalancheBridgeAdapter.InsufficientFee.selector,
                1.5 ether,
                0.1 ether
            )
        );
        adapter.sendMessage{value: 0.1 ether}(keccak256("chain"), hex"beef");
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            keccak256("chain"),
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            keccak256("chain"),
            hex"deadbeef"
        );
    }

    /*//////////////////////////////////////////////////////////////
            RECEIVE MESSAGE (AVALANCHE → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("nullifier-1");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("avax-valset"));
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(keccak256("source-chain"));
        inputs[3] = uint256(keccak256(hex"deadbeef"));

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(proof, inputs, hex"deadbeef");
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function test_receiveMessage_revertsInvalidProof() public {
        warpVerifier.setShouldVerify(false);
        bytes memory proof = new bytes(128);
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("valset"));
        inputs[1] = uint256(keccak256("null"));
        inputs[2] = uint256(keccak256("source"));
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.prank(relayer);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(proof, inputs, hex"beef");
    }

    function test_receiveMessage_revertsDuplicateNullifier() public {
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("nullifier-dup");
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = uint256(keccak256("valset"));
        inputs[1] = uint256(nullifier);
        inputs[2] = uint256(keccak256("source"));
        inputs[3] = uint256(keccak256(hex"beef"));

        vm.startPrank(relayer);
        adapter.receiveMessage(proof, inputs, hex"beef");
        vm.expectRevert(
            abi.encodeWithSelector(
                AvalancheBridgeAdapter.NullifierAlreadyUsed.selector,
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
        vm.expectRevert(AvalancheBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            address(0)
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AvalancheBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"",
            address(0)
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0xBEEF), hex"deadbeef");
        assertEq(fee, 0.001 ether);
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

    function test_isMessageVerified_unknownMessage() public view {
        assertFalse(adapter.isMessageVerified(keccak256("unknown")));
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

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEES
    //////////////////////////////////////////////////////////////*/

    function test_withdrawFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(keccak256("c-chain"), hex"beef");
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
        address to = address(0x456);
        vm.prank(admin);
        adapter.emergencyWithdrawERC20(address(token), to);
        assertEq(token.balanceOf(to), 100 ether);
    }

    function test_receiveETH() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }

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
            keccak256("c-chain"),
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
                    AvalancheBridgeAdapter.FeeTooHigh.selector,
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
        inputs1[0] = uint256(keccak256("valset"));
        inputs1[1] = uint256(nullifier1);
        inputs1[2] = uint256(keccak256("source1"));
        inputs1[3] = uint256(keccak256(hex"beef"));

        uint256[] memory inputs2 = new uint256[](4);
        inputs2[0] = uint256(keccak256("valset"));
        inputs2[1] = uint256(nullifier2);
        inputs2[2] = uint256(keccak256("source2"));
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
