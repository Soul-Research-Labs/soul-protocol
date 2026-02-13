// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LayerZeroAdapter} from "../../contracts/crosschain/LayerZeroAdapter.sol";

/// @dev Mock LayerZero endpoint for testing
contract MockLZEndpoint {
    bool public shouldSucceed = true;

    function setShouldSucceed(bool _val) external {
        shouldSucceed = _val;
    }

    fallback() external payable {
        if (!shouldSucceed) {
            revert("mock fail");
        }
    }

    receive() external payable {}
}

contract LayerZeroAdapterTest is Test {
    LayerZeroAdapter public adapter;
    MockLZEndpoint public endpoint;

    address public admin;
    address public operator;
    address public guardian;
    address public dvn1;
    address public dvn2;
    address public dvn3;
    address public user1;

    bytes32 constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365f804e30c1f4d1;
    bytes32 constant DVN_ROLE =
        0x7935bd0ae54bc31f548c14dba4d37c5c64b3f8ca900cb468fb8abd54d5894f55;

    uint32 constant LOCAL_EID = 30101; // Ethereum mainnet
    uint32 constant ARB_EID = 30110; // Arbitrum

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        guardian = makeAddr("guardian");
        dvn1 = makeAddr("dvn1");
        dvn2 = makeAddr("dvn2");
        dvn3 = makeAddr("dvn3");
        user1 = makeAddr("user1");

        endpoint = new MockLZEndpoint();
        adapter = new LayerZeroAdapter(address(endpoint), LOCAL_EID, admin);

        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(GUARDIAN_ROLE, guardian);

        // Set up DVNs
        vm.startPrank(operator);
        adapter.addDVN(dvn1);
        adapter.addDVN(dvn2);
        adapter.addDVN(dvn3);
        vm.stopPrank();
    }

    // ──────── Helpers ────────

    function _setupTrustedRemote() internal {
        bytes32 remote = bytes32(uint256(uint160(makeAddr("remote"))));
        vm.prank(operator);
        adapter.setTrustedRemote(ARB_EID, remote);
    }

    function _setupUlnConfig() internal {
        address[] memory requiredDVNs = new address[](2);
        requiredDVNs[0] = dvn1;
        requiredDVNs[1] = dvn2;
        address[] memory optionalDVNs = new address[](1);
        optionalDVNs[0] = dvn3;

        LayerZeroAdapter.UlnConfig memory config = LayerZeroAdapter.UlnConfig({
            confirmations: 15,
            requiredDVNCount: 2,
            optionalDVNCount: 1,
            optionalDVNThreshold: 1,
            requiredDVNs: requiredDVNs,
            optionalDVNs: optionalDVNs
        });

        vm.prank(operator);
        adapter.setUlnConfig(ARB_EID, config);
    }

    function _receiveMessage(bytes32 guid, bytes memory payload) internal {
        bytes32 remote = adapter.trustedRemotes(ARB_EID);
        uint64 nonce = adapter.inboundNonce(ARB_EID) + 1;
        vm.prank(address(endpoint));
        adapter.lzReceive(ARB_EID, remote, nonce, guid, payload);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsEndpoint() public view {
        assertEq(adapter.lzEndpoint(), address(endpoint));
    }

    function test_Constructor_SetsLocalEid() public view {
        assertEq(adapter.localEid(), LOCAL_EID);
    }

    function test_Constructor_SetsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_Constructor_RevertZeroEndpoint() public {
        vm.expectRevert(LayerZeroAdapter.InvalidEndpoint.selector);
        new LayerZeroAdapter(address(0), LOCAL_EID, admin);
    }

    function test_Constants() public view {
        assertEq(adapter.MAX_PAYLOAD_SIZE(), 10240);
        assertEq(adapter.DEFAULT_GAS_LIMIT(), 200000);
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE SENDING
    //////////////////////////////////////////////////////////////*/

    function test_SendMessage() public {
        _setupTrustedRemote();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory payload = hex"deadbeef";
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);

        vm.deal(user1, fee + 1 ether);
        vm.prank(user1);
        (bytes32 guid, uint64 nonce) = adapter.sendMessage{value: fee}(
            ARB_EID,
            payload,
            opts
        );

        assertGt(uint256(guid), 0);
        assertEq(nonce, 1);
        assertEq(adapter.outboundNonce(ARB_EID), 1);
    }

    function test_SendMessage_IncrementsNonce() public {
        _setupTrustedRemote();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory payload = hex"aa";
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);

        vm.deal(user1, fee * 3);
        vm.startPrank(user1);
        (, uint64 n1) = adapter.sendMessage{value: fee}(ARB_EID, payload, opts);
        (, uint64 n2) = adapter.sendMessage{value: fee}(ARB_EID, payload, opts);
        vm.stopPrank();

        assertEq(n1, 1);
        assertEq(n2, 2);
    }

    function test_SendMessage_EmitsEvent() public {
        _setupTrustedRemote();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory payload = hex"deadbeef";
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);

        vm.deal(user1, fee);
        vm.prank(user1);
        vm.recordLogs();
        adapter.sendMessage{value: fee}(ARB_EID, payload, opts);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256("MessageSent(uint32,bytes32,bytes,uint256)")
            ) {
                found = true;
                break;
            }
        }
        assertTrue(found, "MessageSent event not emitted");
    }

    function test_SendMessage_RevertUntrustedRemote() public {
        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(LayerZeroAdapter.UntrustedRemote.selector);
        adapter.sendMessage{value: 0.1 ether}(ARB_EID, hex"aa", opts);
    }

    function test_SendMessage_RevertPayloadTooLarge() public {
        _setupTrustedRemote();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory bigPayload = new bytes(10241); // > MAX_PAYLOAD_SIZE

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        vm.expectRevert(LayerZeroAdapter.PayloadTooLarge.selector);
        adapter.sendMessage{value: 5 ether}(ARB_EID, bigPayload, opts);
    }

    function test_SendMessage_RevertInsufficientFee() public {
        _setupTrustedRemote();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        vm.deal(user1, 0.0001 ether);
        vm.prank(user1);
        vm.expectRevert(LayerZeroAdapter.InsufficientFee.selector);
        adapter.sendMessage{value: 0.0001 ether}(ARB_EID, hex"aabb", opts);
    }

    function test_SendMessage_RevertWhenPaused() public {
        _setupTrustedRemote();

        vm.prank(guardian);
        adapter.pause();

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        adapter.sendMessage{value: 0.5 ether}(ARB_EID, hex"aa", opts);
    }

    /*//////////////////////////////////////////////////////////////
                          FEE QUOTING
    //////////////////////////////////////////////////////////////*/

    function test_QuoteSend() public view {
        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory payload = new bytes(64);
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);

        // baseFee + payloadFee + gasFee
        uint256 expected = 0.001 ether +
            (64 * 1000 gwei) /
            32 +
            uint256(200_000) *
            100 gwei;
        assertEq(fee, expected);
    }

    function test_QuoteSend_WithNativeDrop() public view {
        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: 200_000,
                nativeDropAmount: 0.01 ether,
                nativeDropReceiver: user1
            });

        bytes memory payload = new bytes(32);
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);

        // Should include nativeDropAmount
        assertGt(fee, 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE RECEIVING
    //////////////////////////////////////////////////////////////*/

    function test_LzReceive() public {
        _setupTrustedRemote();

        bytes32 guid = keccak256("guid1");
        bytes memory innerPayload = hex"cafe";
        bytes memory lzPayload = abi.encode(user1, uint64(1), innerPayload);

        _receiveMessage(guid, lzPayload);

        assertTrue(adapter.processedMessages(guid));

        (bytes32 rGuid, uint32 rSrcEid, , uint64 rNonce, , , , ) = adapter
            .messageReceipts(guid);

        assertEq(rGuid, guid);
        assertEq(rSrcEid, ARB_EID);
        assertEq(rNonce, 1);
    }

    function test_LzReceive_RevertNotEndpoint() public {
        _setupTrustedRemote();

        bytes32 guid = keccak256("guid2");
        bytes32 remote = adapter.trustedRemotes(ARB_EID);

        vm.prank(user1); // Not endpoint
        vm.expectRevert(LayerZeroAdapter.InvalidEndpoint.selector);
        adapter.lzReceive(ARB_EID, remote, 1, guid, hex"aa");
    }

    function test_LzReceive_RevertUntrustedRemote() public {
        _setupTrustedRemote();

        bytes32 guid = keccak256("guid3");
        bytes32 wrongRemote = bytes32(uint256(0xDEAD));

        vm.prank(address(endpoint));
        vm.expectRevert(LayerZeroAdapter.UntrustedRemote.selector);
        adapter.lzReceive(ARB_EID, wrongRemote, 1, guid, hex"aa");
    }

    function test_LzReceive_RevertAlreadyProcessed() public {
        _setupTrustedRemote();

        bytes32 guid = keccak256("guid4");
        bytes memory payload = abi.encode(user1, uint64(1), hex"aa");

        _receiveMessage(guid, payload);

        bytes32 remote = adapter.trustedRemotes(ARB_EID);
        vm.prank(address(endpoint));
        vm.expectRevert(LayerZeroAdapter.MessageAlreadyProcessed.selector);
        adapter.lzReceive(ARB_EID, remote, 2, guid, payload);
    }

    function test_LzReceive_TracksNonce() public {
        _setupTrustedRemote();

        bytes memory payload1 = abi.encode(user1, uint64(5), hex"aa");
        _receiveMessage(keccak256("g1"), payload1);

        assertEq(adapter.inboundNonce(ARB_EID), 1);

        // Higher nonce updates tracking
        bytes32 remote = adapter.trustedRemotes(ARB_EID);
        vm.prank(address(endpoint));
        adapter.lzReceive(
            ARB_EID,
            remote,
            5,
            keccak256("g2"),
            abi.encode(user1, uint64(5), hex"bb")
        );
        assertEq(adapter.inboundNonce(ARB_EID), 5);
    }

    /*//////////////////////////////////////////////////////////////
                        DVN VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_DVNConfirm() public {
        _setupTrustedRemote();
        _setupUlnConfig();

        bytes32 guid = keccak256("dvn_guid");
        bytes memory payload = abi.encode(user1, uint64(1), hex"aa");
        _receiveMessage(guid, payload);

        vm.prank(dvn1);
        adapter.dvnConfirm(guid);

        (, , , , , , , uint8 dvnConfs) = adapter.messageReceipts(guid);
        assertEq(dvnConfs, 1);
    }

    function test_DVNConfirm_VerifiesOnThreshold() public {
        _setupTrustedRemote();
        _setupUlnConfig();

        bytes32 guid = keccak256("dvn_verify");
        bytes memory payload = abi.encode(user1, uint64(1), hex"bb");
        _receiveMessage(guid, payload);

        // Two confirmations (requiredDVNCount = 2)
        vm.prank(dvn1);
        adapter.dvnConfirm(guid);
        assertFalse(adapter.isMessageVerified(guid));

        vm.prank(dvn2);
        adapter.dvnConfirm(guid);
        assertTrue(adapter.isMessageVerified(guid));
    }

    function test_DVNConfirm_Idempotent() public {
        _setupTrustedRemote();
        _setupUlnConfig();

        bytes32 guid = keccak256("dvn_idem");
        bytes memory payload = abi.encode(user1, uint64(1), hex"cc");
        _receiveMessage(guid, payload);

        vm.prank(dvn1);
        adapter.dvnConfirm(guid);

        // Same DVN confirms again — no increment
        vm.prank(dvn1);
        adapter.dvnConfirm(guid);

        (, , , , , , , uint8 dvnConfs) = adapter.messageReceipts(guid);
        assertEq(dvnConfs, 1);
    }

    function test_DVNConfirm_RevertNotDVN() public {
        vm.prank(user1);
        vm.expectRevert();
        adapter.dvnConfirm(keccak256("none"));
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_SetTrustedRemote() public {
        bytes32 remote = bytes32(uint256(uint160(makeAddr("remote2"))));
        vm.prank(operator);
        adapter.setTrustedRemote(ARB_EID, remote);
        assertEq(adapter.trustedRemotes(ARB_EID), remote);
    }

    function test_SetTrustedRemote_EmitsEvent() public {
        bytes32 remote = bytes32(uint256(42));
        vm.prank(operator);
        vm.expectEmit(true, false, false, true);
        emit LayerZeroAdapter.TrustedRemoteSet(ARB_EID, remote);
        adapter.setTrustedRemote(ARB_EID, remote);
    }

    function test_SetUlnConfig() public {
        _setupUlnConfig();

        LayerZeroAdapter.UlnConfig memory config = adapter.getUlnConfig(
            ARB_EID
        );
        assertEq(config.confirmations, 15);
        assertEq(config.requiredDVNCount, 2);
        assertEq(config.optionalDVNCount, 1);
        assertEq(config.optionalDVNThreshold, 1);
    }

    function test_SetPilHub() public {
        address hub = makeAddr("hub");
        vm.prank(operator);
        adapter.setPilHub(ARB_EID, hub);
        assertEq(adapter.soulHubs(ARB_EID), hub);
    }

    function test_AddDVN() public {
        address newDVN = makeAddr("newDVN");
        vm.prank(operator);
        adapter.addDVN(newDVN);
        assertTrue(adapter.hasRole(DVN_ROLE, newDVN));
    }

    function test_RemoveDVN() public {
        vm.prank(operator);
        adapter.removeDVN(dvn3);
        assertFalse(adapter.hasRole(DVN_ROLE, dvn3));
    }

    function test_Config_RevertNotOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        adapter.setTrustedRemote(ARB_EID, bytes32(uint256(1)));
    }

    /*//////////////////////////////////////////////////////////////
                         PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        vm.prank(guardian);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_Unpause() public {
        vm.prank(guardian);
        adapter.pause();
        vm.prank(guardian);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_Pause_RevertNotGuardian() public {
        vm.prank(user1);
        vm.expectRevert();
        adapter.pause();
    }

    /*//////////////////////////////////////////////////////////////
                         RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    function test_ReceiveETH() public {
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsMessageVerified_Default() public view {
        assertFalse(adapter.isMessageVerified(keccak256("nonexistent")));
    }

    function test_GetUlnConfig_Default() public view {
        LayerZeroAdapter.UlnConfig memory config = adapter.getUlnConfig(99999);
        assertEq(config.confirmations, 0);
        assertEq(config.requiredDVNCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_QuoteSend(
        uint128 gasLimit,
        uint16 payloadLen
    ) public view {
        gasLimit = uint128(bound(gasLimit, 1, 1_000_000));
        payloadLen = uint16(bound(payloadLen, 1, 1024));

        LayerZeroAdapter.ExecutorOptions memory opts = LayerZeroAdapter
            .ExecutorOptions({
                gasLimit: gasLimit,
                nativeDropAmount: 0,
                nativeDropReceiver: address(0)
            });

        bytes memory payload = new bytes(payloadLen);
        uint256 fee = adapter.quoteSend(ARB_EID, payload, opts);
        assertGt(fee, 0);
    }

    function testFuzz_LzReceiveUniqueGuids(bytes32 guid) public {
        vm.assume(guid != bytes32(0));
        _setupTrustedRemote();

        bytes memory payload = abi.encode(user1, uint64(1), hex"aa");
        _receiveMessage(guid, payload);

        assertTrue(adapter.processedMessages(guid));
    }
}
