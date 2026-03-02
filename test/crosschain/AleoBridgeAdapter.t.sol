// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AleoBridgeAdapter, IAleoRelay, IAleoLightClient} from "../../contracts/crosschain/AleoBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockAleoRelay {
    uint256 public relayFee = 0.001 ether;

    function sendToAleo(
        bytes32,
        bytes32,
        bytes calldata
    ) external payable returns (bytes32) {
        return keccak256(abi.encodePacked(msg.sender, block.timestamp));
    }

    function getRelayFee() external view returns (uint256) {
        return relayFee;
    }

    function setRelayFee(uint256 _fee) external {
        relayFee = _fee;
    }
}

contract MockAleoLightClient {
    bool public shouldVerify = true;
    bytes32 public committeeHash = bytes32(uint256(0x1234));

    function verifyBlockHeader(
        bytes32,
        uint64,
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

    function currentCommitteeHash() external view returns (bytes32) {
        return committeeHash;
    }

    function setShouldVerify(bool _verify) external {
        shouldVerify = _verify;
    }
}

contract MockERC20Aleo is ERC20 {
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

contract AleoBridgeAdapterTest is Test {
    AleoBridgeAdapter public adapter;
    MockAleoRelay public relay;
    MockAleoLightClient public lightClient;
    MockERC20Aleo public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);

    bytes32 constant ALEO_PROGRAM = keccak256("bridge.aleo");
    bytes32 constant ALEO_FUNCTION = keccak256("bridge_receive");

    function setUp() public {
        vm.deal(admin, 100 ether);
        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(user, 100 ether);

        relay = new MockAleoRelay();
        lightClient = new MockAleoLightClient();
        token = new MockERC20Aleo();

        vm.startPrank(admin);
        adapter = new AleoBridgeAdapter(address(relay), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.whitelistProgram(ALEO_PROGRAM, true);
        adapter.setAleoLightClient(address(lightClient));
        adapter.setAleoBridgeProgram(ALEO_PROGRAM);
        adapter.setMinMessageFee(0.001 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsRelay() public view {
        assertEq(address(adapter.aleoRelay()), address(relay));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revertsZeroRelay() public {
        vm.expectRevert(AleoBridgeAdapter.ZeroAddress.selector);
        new AleoBridgeAdapter(address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(AleoBridgeAdapter.ZeroAddress.selector);
        new AleoBridgeAdapter(address(relay), address(0));
    }

    function test_constructor_enablesMainnet() public view {
        assertTrue(adapter.supportedNetworks(0));
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.ALEO_CHAIN_ID(), 17100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 500);
        assertEq(adapter.COMMITTEE_QUORUM_BPS(), 6667);
        assertEq(adapter.MIN_PROOF_LENGTH(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                      VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeType() public view {
        assertEq(keccak256(bytes(adapter.bridgeType())), keccak256("ALEO"));
    }

    function test_chainId() public view {
        assertEq(adapter.chainId(), 17100);
    }

    function test_isProgramWhitelisted() public view {
        assertTrue(adapter.isProgramWhitelisted(ALEO_PROGRAM));
        assertFalse(adapter.isProgramWhitelisted(bytes32(uint256(0xBAD))));
    }

    function test_verifyStateProof_returnsTrue() public view {
        assertTrue(
            adapter.verifyStateProof(
                bytes32(uint256(1)),
                abi.encodePacked(bytes32(uint256(2)))
            )
        );
    }

    function test_verifyStateProof_failsNoClient() public {
        // Deploy adapter without light client
        vm.prank(admin);
        AleoBridgeAdapter adapter2 = new AleoBridgeAdapter(
            address(relay),
            admin
        );
        assertFalse(adapter2.verifyStateProof(bytes32(0), hex"abcd"));
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_setAleoRelay() public {
        address newRelay = address(0x999);
        vm.prank(admin);
        adapter.setAleoRelay(newRelay);
        assertEq(address(adapter.aleoRelay()), newRelay);
    }

    function test_setAleoRelay_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AleoBridgeAdapter.ZeroAddress.selector);
        adapter.setAleoRelay(address(0));
    }

    function test_setAleoRelay_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setAleoRelay(address(0x999));
    }

    function test_setAleoLightClient() public {
        address newClient = address(0x888);
        vm.prank(admin);
        adapter.setAleoLightClient(newClient);
        assertEq(address(adapter.aleoLightClient()), newClient);
    }

    function test_whitelistProgram() public {
        bytes32 newProgram = keccak256("pool.aleo");
        vm.prank(admin);
        adapter.whitelistProgram(newProgram, true);
        assertTrue(adapter.whitelistedPrograms(newProgram));
    }

    function test_whitelistProgram_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AleoBridgeAdapter.InvalidProgramId.selector);
        adapter.whitelistProgram(bytes32(0), true);
    }

    function test_setAleoBridgeProgram() public {
        bytes32 prog = keccak256("new_bridge.aleo");
        vm.prank(admin);
        adapter.setAleoBridgeProgram(prog);
        assertEq(adapter.aleoBridgeProgram(), prog);
    }

    function test_setAleoBridgeProgram_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AleoBridgeAdapter.InvalidProgramId.selector);
        adapter.setAleoBridgeProgram(bytes32(0));
    }

    function test_setSupportedNetwork() public {
        vm.prank(admin);
        adapter.setSupportedNetwork(1, true);
        assertTrue(adapter.supportedNetworks(1));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(100);
        assertEq(adapter.bridgeFeeBps(), 100);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(AleoBridgeAdapter.FeeTooHigh.selector, 501)
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
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"aa"
        );
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"bb"
        );
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsProgramNotWhitelisted() public {
        bytes32 unknownProg = bytes32(uint256(0xBAD));
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                AleoBridgeAdapter.ProgramNotWhitelisted.selector,
                unknownProg
            )
        );
        adapter.sendMessage{value: 0.01 ether}(
            unknownProg,
            ALEO_FUNCTION,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsInvalidProgramId() public {
        vm.prank(operator);
        vm.expectRevert(AleoBridgeAdapter.InvalidProgramId.selector);
        adapter.sendMessage{value: 0.01 ether}(
            bytes32(0),
            ALEO_FUNCTION,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AleoBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex""
        );
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(AleoBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            longPayload
        );
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"deadbeef"
        );
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            hex"beef"
        );

        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
                      RECEIVE MESSAGE
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 nullifier = keccak256("test_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        // Proof: 32 bytes stateRoot + 32+ bytes proof
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);

        assertTrue(hash != bytes32(0));
        assertTrue(adapter.verifiedMessages(hash));
        assertTrue(adapter.usedNullifiers(nullifier));
        assertEq(adapter.totalMessagesReceived(), 1);
    }

    function test_receiveMessage_revertsNetworkNotSupported() public {
        bytes32 nullifier = keccak256("test_null2");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AleoBridgeAdapter.NetworkNotSupported.selector,
                5
            )
        );
        adapter.receiveMessage(ALEO_PROGRAM, 5, payload, proof);
    }

    function test_receiveMessage_revertsProgramNotWhitelisted() public {
        bytes32 unknownProg = bytes32(uint256(0xBAD));
        bytes32 nullifier = keccak256("test_null3");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AleoBridgeAdapter.ProgramNotWhitelisted.selector,
                unknownProg
            )
        );
        adapter.receiveMessage(unknownProg, 0, payload, proof);
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );
        vm.prank(relayer);
        vm.expectRevert(AleoBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(ALEO_PROGRAM, 0, hex"", proof);
    }

    function test_receiveMessage_revertsShortProof() public {
        bytes32 nullifier = keccak256("test_null4");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");

        vm.prank(relayer);
        vm.expectRevert(AleoBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, hex"abcd");
    }

    function test_receiveMessage_revertsNullifierReuse() public {
        bytes32 nullifier = keccak256("reuse_null");
        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AleoBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
    }

    function test_receiveMessage_revertsNonRelayer() public {
        bytes32 nullifier = keccak256("test_null5");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
    }

    function test_receiveMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();

        bytes32 nullifier = keccak256("test_null6");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
    }

    function test_receiveMessage_revertsInvalidProofFromLightClient() public {
        lightClient.setShouldVerify(false);

        bytes32 nullifier = keccak256("test_null7");
        bytes memory payload = abi.encodePacked(nullifier, hex"beef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        vm.expectRevert(AleoBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
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
        assertEq(fee, 0.001 ether + 0.001 ether); // relay + min
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
        adapter.sendMessage{value: 1 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
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
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            ALEO_PROGRAM,
            ALEO_FUNCTION,
            payload
        );
        assertTrue(hash != bytes32(0));
    }

    function testFuzz_receiveMessage(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
        assertTrue(hash != bytes32(0));
        assertTrue(adapter.usedNullifiers(nullifier));
    }

    function testFuzz_nullifierReplay(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes memory payload = abi.encodePacked(nullifier, hex"deadbeef");
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(relayer);
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                AleoBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(ALEO_PROGRAM, 0, payload, proof);
    }
}
