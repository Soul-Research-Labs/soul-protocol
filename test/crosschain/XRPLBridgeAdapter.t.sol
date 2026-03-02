// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {XRPLBridgeAdapter, IXRPLBridge, IXRPLLightClient} from "../../contracts/crosschain/XRPLBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockXRPLBridge {
    uint256 public relayFee = 0.001 ether;

    function sendToXRPL(
        bytes20,
        uint32,
        bytes calldata
    ) external payable returns (bytes32) {
        return keccak256(abi.encodePacked(msg.sender, block.timestamp));
    }

    function verifyAttestation(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function getRelayFee() external view returns (uint256) {
        return relayFee;
    }

    function setRelayFee(uint256 _fee) external {
        relayFee = _fee;
    }
}

contract MockXRPLLightClient {
    bool public shouldVerify = true;
    uint64 public latestLedger = 1000;

    function verifyLedgerHeader(
        uint64,
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyObjectProof(
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function latestVerifiedLedger() external view returns (uint64) {
        return latestLedger;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

contract MockERC20XRPL is ERC20 {
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

contract XRPLBridgeAdapterTest is Test {
    XRPLBridgeAdapter public adapter;
    MockXRPLBridge public bridge;
    MockXRPLLightClient public lightClient;
    MockERC20XRPL public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);

    bytes20 constant XRPL_ACCOUNT = bytes20(uint160(0xCAFECAFECAFECAFECAFE));
    uint32 constant DEST_TAG = 12345;

    function setUp() public {
        vm.deal(admin, 100 ether);
        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(user, 100 ether);

        bridge = new MockXRPLBridge();
        lightClient = new MockXRPLLightClient();
        token = new MockERC20XRPL();

        vm.startPrank(admin);
        adapter = new XRPLBridgeAdapter(address(bridge), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.whitelistAccount(XRPL_ACCOUNT, true);
        adapter.setXRPLLightClient(address(lightClient));
        adapter.setDefaultDestinationTag(DEST_TAG);
        adapter.setMinMessageFee(0.001 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsBridge() public view {
        assertEq(address(adapter.xrplBridge()), address(bridge));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(XRPLBridgeAdapter.ZeroAddress.selector);
        new XRPLBridgeAdapter(address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(XRPLBridgeAdapter.ZeroAddress.selector);
        new XRPLBridgeAdapter(address(bridge), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.XRPL_CHAIN_ID(), 18100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 500);
        assertEq(adapter.ATTESTATION_THRESHOLD_BPS(), 8000);
        assertEq(adapter.MIN_ATTESTATION_LENGTH(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                      VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeType() public view {
        assertEq(keccak256(bytes(adapter.bridgeType())), keccak256("XRPL"));
    }

    function test_chainId() public view {
        assertEq(adapter.chainId(), 18100);
    }

    function test_isAccountWhitelisted() public view {
        assertTrue(adapter.isAccountWhitelisted(XRPL_ACCOUNT));
        assertFalse(adapter.isAccountWhitelisted(bytes20(uint160(0xBAD))));
    }

    function test_verifyLedgerProof_returnsTrue() public view {
        assertTrue(
            adapter.verifyLedgerProof(
                bytes32(uint256(1)),
                abi.encodePacked(bytes32(uint256(2)))
            )
        );
    }

    function test_verifyLedgerProof_failsNoClient() public {
        vm.prank(admin);
        XRPLBridgeAdapter adapter2 = new XRPLBridgeAdapter(
            address(bridge),
            admin
        );
        assertFalse(adapter2.verifyLedgerProof(bytes32(0), hex"abcd"));
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_setXRPLBridge() public {
        address newBridge = address(0x999);
        vm.prank(admin);
        adapter.setXRPLBridge(newBridge);
        assertEq(address(adapter.xrplBridge()), newBridge);
    }

    function test_setXRPLBridge_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(XRPLBridgeAdapter.ZeroAddress.selector);
        adapter.setXRPLBridge(address(0));
    }

    function test_setXRPLBridge_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setXRPLBridge(address(0x999));
    }

    function test_setXRPLLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setXRPLLightClient(newClient);
        assertEq(address(adapter.xrplLightClient()), newClient);
    }

    function test_whitelistAccount() public {
        bytes20 newAccount = bytes20(uint160(0xBEEF));
        vm.prank(admin);
        adapter.whitelistAccount(newAccount, true);
        assertTrue(adapter.whitelistedAccounts(newAccount));
    }

    function test_whitelistAccount_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(XRPLBridgeAdapter.InvalidAccount.selector);
        adapter.whitelistAccount(bytes20(0), true);
    }

    function test_setDefaultDestinationTag() public {
        vm.prank(admin);
        adapter.setDefaultDestinationTag(99999);
        assertEq(adapter.defaultDestinationTag(), 99999);
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);
        assertEq(adapter.bridgeFeeBps(), 100);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(XRPLBridgeAdapter.FeeTooHigh.selector, 501)
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
            XRPL_ACCOUNT,
            DEST_TAG,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(XRPL_ACCOUNT, DEST_TAG, hex"aa");
        adapter.sendMessage{value: 0.01 ether}(XRPL_ACCOUNT, DEST_TAG, hex"bb");
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsAccountNotWhitelisted() public {
        bytes20 unknownAccount = bytes20(uint160(0xBAD));
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                XRPLBridgeAdapter.AccountNotWhitelisted.selector,
                unknownAccount
            )
        );
        adapter.sendMessage{value: 0.01 ether}(
            unknownAccount,
            DEST_TAG,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsInvalidAccount() public {
        vm.prank(operator);
        vm.expectRevert(XRPLBridgeAdapter.InvalidAccount.selector);
        adapter.sendMessage{value: 0.01 ether}(
            bytes20(0),
            DEST_TAG,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(XRPLBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(XRPL_ACCOUNT, DEST_TAG, hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(XRPLBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(
            XRPL_ACCOUNT,
            DEST_TAG,
            longPayload
        );
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            XRPL_ACCOUNT,
            DEST_TAG,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            XRPL_ACCOUNT,
            DEST_TAG,
            hex"deadbeef"
        );
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(XRPL_ACCOUNT, DEST_TAG, hex"beef");

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
                      RECEIVE MESSAGE
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 nullifier = keccak256("test_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        // Attestation: 32 bytes ledgerHash + 32+ bytes proof
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            XRPL_ACCOUNT,
            100,
            payload,
            attestation
        );

        assertTrue(hash != bytes32(0));
        assertTrue(adapter.verifiedMessages(hash));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsAccountNotWhitelisted() public {
        bytes20 unknownAccount = bytes20(uint160(0xBAD));
        bytes32 nullifier = keccak256("test_null2");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                XRPLBridgeAdapter.AccountNotWhitelisted.selector,
                unknownAccount
            )
        );
        adapter.receiveMessage(unknownAccount, 100, payload, attestation);
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );
        vm.prank(relayer);
        vm.expectRevert(XRPLBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(XRPL_ACCOUNT, 100, hex"", attestation);
    }

    function test_receiveMessage_revertsShortAttestation() public {
        bytes32 nullifier = keccak256("test_null3");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");

        vm.prank(relayer);
        vm.expectRevert(XRPLBridgeAdapter.InvalidAttestation.selector);
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, hex"abcd");
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = keccak256("reuse_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                XRPLBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);
    }

    function test_receiveMessage_revertsNonRelayer() public {
        bytes32 nullifier = keccak256("test_null4");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();

        bytes32 nullifier = keccak256("test_null5");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);
    }

    function test_receiveMessage_revertsInvalidProofFromLightClient() public {
        lightClient.setShouldVerify(false);

        bytes32 nullifier = keccak256("test_null6");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert(XRPLBridgeAdapter.InvalidLedgerProof.selector);
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);
    }

    /*//////////////////////////////////////////////////////////////
                      IBRIDGEADAPTER
    //////////////////////////////////////////////////////////////*/

    function test_bridgeMessage_success() public {
        vm.prank(user);
        bytes32 id = adapter.bridgeMessage{value: 0.01 ether}(
            address(uint160(uint256(uint160(bytes20(XRPL_ACCOUNT))))),
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
        adapter.sendMessage{value: 1 ether}(XRPL_ACCOUNT, DEST_TAG, hex"beef");

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
            XRPL_ACCOUNT,
            DEST_TAG,
            payload
        );
        assertTrue(hash != bytes32(0));
    }

    function testFuzz_receiveMessage(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            XRPL_ACCOUNT,
            100,
            payload,
            attestation
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function testFuzz_nullifierReplay(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory attestation = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                XRPLBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(XRPL_ACCOUNT, 100, payload, attestation);
    }
}
