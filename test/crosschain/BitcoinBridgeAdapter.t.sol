// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {BitcoinBridgeAdapter, IBitcoinBridge, IBitcoinRelay} from "../../contracts/crosschain/BitcoinBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockBitcoinBridge {
    uint256 public bridgeFee = 0.001 ether;

    function sendToBitcoin(
        bytes32,
        bytes calldata
    ) external payable returns (bytes32) {
        return keccak256(abi.encodePacked(msg.sender, block.timestamp));
    }

    function getBridgeFee() external view returns (uint256) {
        return bridgeFee;
    }

    function setBridgeFee(uint256 _fee) external {
        bridgeFee = _fee;
    }
}

contract MockBitcoinRelay {
    uint256 public bestHeight = 850000;
    bool public shouldVerify = true;

    function verifyTx(
        bytes32,
        bytes32,
        uint256,
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldVerify;
    }

    function getBestKnownHeight() external view returns (uint256) {
        return bestHeight;
    }

    function setBestHeight(uint256 _height) external {
        bestHeight = _height;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

contract MockERC20BTC is ERC20 {
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

contract BitcoinBridgeAdapterTest is Test {
    BitcoinBridgeAdapter public adapter;
    MockBitcoinBridge public bridge;
    MockBitcoinRelay public relay;
    MockERC20BTC public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);

    bytes32 constant BTC_ADDRESS = bytes32(uint256(0xCAFE));
    bytes32 constant BTC_TX_HASH = bytes32(uint256(0xDEAD));

    function setUp() public {
        vm.deal(admin, 100 ether);
        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(user, 100 ether);

        bridge = new MockBitcoinBridge();
        relay = new MockBitcoinRelay();
        token = new MockERC20BTC();

        vm.startPrank(admin);
        adapter = new BitcoinBridgeAdapter(
            address(bridge),
            address(relay),
            admin
        );
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.whitelistAddress(BTC_ADDRESS, true);
        adapter.setMinMessageFee(0.001 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsBridge() public view {
        assertEq(address(adapter.bitcoinBridge()), address(bridge));
    }

    function test_constructor_setsRelay() public view {
        assertEq(address(adapter.bitcoinRelay()), address(relay));
    }

    function test_constructor_setsConfirmations() public view {
        assertEq(adapter.requiredConfirmations(), 6);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(BitcoinBridgeAdapter.ZeroAddress.selector);
        new BitcoinBridgeAdapter(address(0), address(relay), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(BitcoinBridgeAdapter.ZeroAddress.selector);
        new BitcoinBridgeAdapter(address(bridge), address(relay), address(0));
    }

    function test_constructor_allowsZeroRelay() public {
        // Relay is optional
        BitcoinBridgeAdapter a = new BitcoinBridgeAdapter(
            address(bridge),
            address(0),
            admin
        );
        assertEq(address(a.bitcoinRelay()), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.BITCOIN_CHAIN_ID(), 19100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 500);
        assertEq(adapter.DEFAULT_CONFIRMATIONS(), 6);
        assertEq(adapter.MIN_SPV_PROOF_LENGTH(), 80);
    }

    /*//////////////////////////////////////////////////////////////
                      VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeType() public view {
        assertEq(keccak256(bytes(adapter.bridgeType())), keccak256("BITCOIN"));
    }

    function test_chainId() public view {
        assertEq(adapter.chainId(), 19100);
    }

    function test_isAddressWhitelisted() public view {
        assertTrue(adapter.isAddressWhitelisted(BTC_ADDRESS));
        assertFalse(adapter.isAddressWhitelisted(bytes32(uint256(0xBAD))));
    }

    function test_isBtcTxProcessed() public view {
        assertFalse(adapter.isBtcTxProcessed(BTC_TX_HASH));
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_setBitcoinBridge() public {
        address newBridge = address(0x999);
        vm.prank(admin);
        adapter.setBitcoinBridge(newBridge);
        assertEq(address(adapter.bitcoinBridge()), newBridge);
    }

    function test_setBitcoinBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(BitcoinBridgeAdapter.ZeroAddress.selector);
        adapter.setBitcoinBridge(address(0));
    }

    function test_setBitcoinBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setBitcoinBridge(address(0x999));
    }

    function test_setBitcoinRelay() public {
        address newRelay = address(0x888);
        vm.prank(admin);
        adapter.setBitcoinRelay(newRelay);
        assertEq(address(adapter.bitcoinRelay()), newRelay);
    }

    function test_whitelistAddress() public {
        bytes32 newAddr = bytes32(uint256(0xBEEF));
        vm.prank(admin);
        adapter.whitelistAddress(newAddr, true);
        assertTrue(adapter.whitelistedAddresses(newAddr));
    }

    function test_whitelistAddress_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidBtcAddress.selector);
        adapter.whitelistAddress(bytes32(0), true);
    }

    function test_setRequiredConfirmations() public {
        vm.prank(admin);
        adapter.setRequiredConfirmations(12);
        assertEq(adapter.requiredConfirmations(), 12);
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);
        assertEq(adapter.bridgeFeeBps(), 100);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.FeeTooHigh.selector,
                501
            )
        );
        adapter.setBridgeFee(501);
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
            BTC_ADDRESS,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, hex"aa");
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, hex"bb");
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsAddressNotWhitelisted() public {
        bytes32 unknownAddr = bytes32(uint256(0xBAD));
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.AddressNotWhitelisted.selector,
                unknownAddr
            )
        );
        adapter.sendMessage{value: 0.01 ether}(unknownAddr, hex"deadbeef");
    }

    function test_sendMessage_revertsInvalidAddress() public {
        vm.prank(operator);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidBtcAddress.selector);
        adapter.sendMessage{value: 0.01 ether}(bytes32(0), hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, longPayload);
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, hex"deadbeef");
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(BTC_ADDRESS, hex"deadbeef");
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(BTC_ADDRESS, hex"beef");

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
                      RECEIVE MESSAGE
    //////////////////////////////////////////////////////////////*/

    function _makeSpvProof() internal pure returns (bytes memory) {
        // blockHash (32) + txIndex (32) + merkle proof (32 * n)
        return
            abi.encodePacked(
                bytes32(uint256(0xBEEF)),
                bytes32(uint256(0)),
                bytes32(uint256(0xABCD))
            );
    }

    function test_receiveMessage_success() public {
        bytes32 nullifier = keccak256("test_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            BTC_TX_HASH,
            849990,
            payload,
            spvProof
        );

        assertTrue(hash != bytes32(0));
        assertTrue(adapter.verifiedMessages(hash));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertTrue(adapter.processedBtcTxs(BTC_TX_HASH));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsDuplicateTx() public {
        bytes32 nullifier1 = keccak256("test_null1");
        bytes32 nullifier2 = keccak256("test_null2");
        bytes memory payload1 = abi.encodePacked(nullifier1, hex"beef");
        bytes memory payload2 = abi.encodePacked(nullifier2, hex"cafe");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        adapter.receiveMessage(BTC_TX_HASH, 849990, payload1, spvProof);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.BtcTxAlreadyProcessed.selector,
                BTC_TX_HASH
            )
        );
        adapter.receiveMessage(BTC_TX_HASH, 849990, payload2, spvProof);
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        bytes memory spvProof = _makeSpvProof();
        vm.prank(relayer);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(BTC_TX_HASH, 849990, hex"", spvProof);
    }

    function test_receiveMessage_revertsShortProof() public {
        bytes32 nullifier = keccak256("test_null3");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");

        vm.prank(relayer);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidSPVProof.selector);
        adapter.receiveMessage(BTC_TX_HASH, 849990, payload, hex"abcd");
    }

    function test_receiveMessage_revertsInsufficientConfirmations() public {
        // Best height = 850000, tx at 849999, need 6 confs → 850005 needed
        bytes32 nullifier = keccak256("test_null4");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.InsufficientConfirmations.selector,
                6,
                1
            )
        );
        adapter.receiveMessage(
            bytes32(uint256(0x111)),
            849999,
            payload,
            spvProof
        );
    }

    function test_receiveMessage_revertsInvalidSPVFromRelay() public {
        relay.setShouldVerify(false);

        bytes32 nullifier = keccak256("test_null5");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        vm.expectRevert(BitcoinBridgeAdapter.InvalidSPVProof.selector);
        adapter.receiveMessage(
            bytes32(uint256(0x222)),
            849990,
            payload,
            spvProof
        );
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = keccak256("reuse_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        adapter.receiveMessage(
            bytes32(uint256(0x333)),
            849990,
            payload,
            spvProof
        );

        // Different tx hash but same nullifier
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(
            bytes32(uint256(0x444)),
            849990,
            payload,
            spvProof
        );
    }

    function test_receiveMessage_revertsNonRelayer() public {
        bytes32 nullifier = keccak256("test_null6");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(
            bytes32(uint256(0x555)),
            849990,
            payload,
            spvProof
        );
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();

        bytes32 nullifier = keccak256("test_null7");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(
            bytes32(uint256(0x666)),
            849990,
            payload,
            spvProof
        );
    }

    function test_receiveMessage_worksWithoutRelay() public {
        // Deploy adapter without relay
        vm.startPrank(admin);
        BitcoinBridgeAdapter adapter2 = new BitcoinBridgeAdapter(
            address(bridge),
            address(0),
            admin
        );
        adapter2.grantRole(adapter2.RELAYER_ROLE(), relayer);
        adapter2.whitelistAddress(BTC_ADDRESS, true);
        vm.stopPrank();

        bytes32 nullifier = keccak256("no_relay_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        // Without relay, SPV proof still must meet min length but isn't verified
        bytes memory spvProof = new bytes(80);

        vm.prank(relayer);
        bytes32 hash = adapter2.receiveMessage(
            bytes32(uint256(0x777)),
            849990,
            payload,
            spvProof
        );
        assertTrue(hash != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                      IBRIDGEADAPTER
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        vm.prank(user);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(0x123),
            hex"deadbeef",
            user
        );
        assertTrue(id != bytes32(0));
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0x123), hex"deadbeef");
        assertEq(fee, 0.001 ether + 0.001 ether);
    }

    function test_isMessageVerified_false() public view {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(0xDEAD))));
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
        adapter.sendMessage{value: 1 ether}(BTC_ADDRESS, hex"beef");

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
            BTC_ADDRESS,
            payload
        );
        assertTrue(hash != bytes32(0));
    }

    function testFuzz_receiveMessage(bytes32 txHash, bytes32 nullifier) public {
        vm.assume(txHash != bytes32(0));
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            txHash,
            849990,
            payload,
            spvProof
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.processedBtcTxs(txHash));
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function testFuzz_nullifierReplay(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory spvProof = _makeSpvProof();

        vm.prank(relayer);
        adapter.receiveMessage(
            bytes32(uint256(0xA1)),
            849990,
            payload,
            spvProof
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitcoinBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(
            bytes32(uint256(0xA2)),
            849990,
            payload,
            spvProof
        );
    }
}
