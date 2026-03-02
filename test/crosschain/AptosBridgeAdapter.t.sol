// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AptosBridgeAdapter, IAptosLayerZeroEndpoint, IAptosLightClient} from "../../contracts/crosschain/AptosBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockAptosLZEndpoint {
    uint256 public estimatedFee = 0.001 ether;

    function send(
        uint16,
        bytes calldata,
        bytes calldata,
        address payable,
        bytes calldata
    ) external payable {}

    function estimateFees(
        uint16,
        bytes calldata,
        bytes calldata
    ) external view returns (uint256, uint256) {
        return (estimatedFee, 0);
    }

    function hasStoredPayload(
        uint16,
        bytes calldata,
        uint64
    ) external pure returns (bool) {
        return false;
    }

    function setEstimatedFee(uint256 _fee) external {
        estimatedFee = _fee;
    }
}

contract MockAptosLightClient {
    bool public shouldVerify = true;
    uint64 public ledgerVersion = 500_000;

    function verifyStateProof(
        bytes32,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function latestLedgerVersion() external view returns (uint64) {
        return ledgerVersion;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

contract MockERC20Aptos is ERC20 {
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

contract AptosBridgeAdapterTest is Test {
    AptosBridgeAdapter public adapter;
    MockAptosLZEndpoint public endpoint;
    MockAptosLightClient public lightClient;
    MockERC20Aptos public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    uint16 constant LZ_APTOS = 108;
    bytes constant TRUSTED_REMOTE = hex"0000000000000000000000000000000000000000000000000000000000CAFE";

    function setUp() public {
        endpoint = new MockAptosLZEndpoint();
        lightClient = new MockAptosLightClient();
        token = new MockERC20Aptos();

        adapter = new AptosBridgeAdapter(address(endpoint), admin);

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        adapter.setTrustedRemote(LZ_APTOS, TRUSTED_REMOTE);
        adapter.setAptosLightClient(address(lightClient));
        vm.stopPrank();

        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsEndpoint() public view {
        assertEq(address(adapter.lzEndpoint()), address(endpoint));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_setsDefaultAdapterParams() public view {
        bytes memory params = adapter.defaultAdapterParams();
        assertTrue(params.length > 0);
    }

    function test_constructor_revertsZeroEndpoint() public {
        vm.expectRevert(AptosBridgeAdapter.InvalidEndpoint.selector);
        new AptosBridgeAdapter(address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(AptosBridgeAdapter.InvalidTarget.selector);
        new AptosBridgeAdapter(address(endpoint), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.APTOS_CHAIN_ID(), 15_100);
        assertEq(adapter.LZ_APTOS_CHAIN_ID(), 108);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 15_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Aptos");
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

    function test_setLzEndpoint() public {
        address newEndpoint = address(0x999);
        vm.prank(admin);
        adapter.setLzEndpoint(newEndpoint);
        assertEq(address(adapter.lzEndpoint()), newEndpoint);
    }

    function test_setLzEndpoint_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AptosBridgeAdapter.InvalidEndpoint.selector);
        adapter.setLzEndpoint(address(0));
    }

    function test_setLzEndpoint_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setLzEndpoint(address(0x999));
    }

    function test_setAptosLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setAptosLightClient(newClient);
        assertEq(address(adapter.aptosLightClient()), newClient);
    }

    function test_setTrustedRemote() public {
        bytes memory remote = hex"BEEF";
        vm.prank(admin);
        adapter.setTrustedRemote(LZ_APTOS, remote);
        assertEq(adapter.trustedRemotes(LZ_APTOS), remote);
    }

    function test_setDefaultAdapterParams() public {
        bytes memory newParams = abi.encodePacked(uint16(2), uint256(500_000));
        vm.prank(admin);
        adapter.setDefaultAdapterParams(newParams);
        assertEq(adapter.defaultAdapterParams(), newParams);
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
                AptosBridgeAdapter.FeeTooHigh.selector,
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
              SEND MESSAGE (ZASEON → Aptos)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        bytes memory aptosTarget = hex"0000000000000000000000000000000000000000000000000000000000CAFE";
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            aptosTarget,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        bytes memory target = hex"CAFE";
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(target, hex"aa");
        adapter.sendMessage{value: 0.01 ether}(target, hex"bb");
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsEmptyTarget() public {
        vm.prank(operator);
        vm.expectRevert(AptosBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(hex"", hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AptosBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(hex"CAFE", hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(AptosBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(hex"CAFE", longPayload);
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(hex"CAFE", hex"deadbeef");
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(hex"CAFE", hex"deadbeef");
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(hex"CAFE", hex"beef");

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (Aptos → ZASEON)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            hex"deadbeef"
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            LZ_APTOS,
            TRUSTED_REMOTE,
            payload
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsWrongChain() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AptosBridgeAdapter.InvalidSourceChain.selector,
                99
            )
        );
        adapter.receiveMessage(99, TRUSTED_REMOTE, hex"deadbeef");
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        vm.prank(relayer);
        vm.expectRevert(AptosBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, hex"");
    }

    function test_receiveMessage_revertsUntrustedRemote() public {
        // Remove trusted remote
        vm.prank(admin);
        adapter.setTrustedRemote(LZ_APTOS, hex"");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AptosBridgeAdapter.UntrustedRemote.selector,
                LZ_APTOS,
                TRUSTED_REMOTE
            )
        );
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, hex"deadbeef");
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = bytes32(uint256(42));
        bytes memory payload = abi.encodePacked(nullifier, hex"aa");

        vm.startPrank(relayer);
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, payload);

        vm.expectRevert(
            abi.encodeWithSelector(
                AptosBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, payload);
        vm.stopPrank();
    }

    function test_receiveMessage_revertsNonRelayer() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, hex"deadbeef");
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(LZ_APTOS, TRUSTED_REMOTE, hex"deadbeef");
    }

    /*//////////////////////////////////////////////////////////////
                    STATE PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_verifyStateProof_success() public view {
        bytes32 root = bytes32(uint256(0x12345));
        bytes memory proof = new bytes(64);
        assertTrue(adapter.verifyStateProof(root, proof));
    }

    function test_verifyStateProof_failsShortProof() public view {
        assertFalse(adapter.verifyStateProof(bytes32(0), hex"abcd"));
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
        vm.expectRevert(AptosBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            operator
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AptosBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0x123),
            hex"",
            operator
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0x123), hex"deadbeef");
        assertEq(fee, 0.001 ether); // Mock LZ endpoint estimated fee
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
        adapter.sendMessage{value: 1 ether}(hex"CAFE", hex"beef");

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
            hex"CAFE",
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
                AptosBridgeAdapter.FeeTooHigh.selector,
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
            LZ_APTOS,
            TRUSTED_REMOTE,
            payload
        );
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
    }
}
