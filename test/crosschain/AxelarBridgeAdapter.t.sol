// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AxelarBridgeAdapter, IAxelarGateway, IAxelarGasService} from "../../contracts/crosschain/AxelarBridgeAdapter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockAxelarGateway {
    bool public shouldApprove = true;
    mapping(bytes32 => bool) public executedCommands;

    function callContract(
        string calldata,
        string calldata,
        bytes calldata
    ) external {}

    function callContractWithToken(
        string calldata,
        string calldata,
        bytes calldata,
        string calldata,
        uint256
    ) external {}

    function isCommandExecuted(bytes32 commandId) external view returns (bool) {
        return executedCommands[commandId];
    }

    function validateContractCall(
        bytes32,
        string calldata,
        string calldata,
        bytes32
    ) external returns (bool) {
        return shouldApprove;
    }

    function setShouldApprove(bool _approve) external {
        shouldApprove = _approve;
    }

    function setCommandExecuted(bytes32 _commandId) external {
        executedCommands[_commandId] = true;
    }
}

contract MockAxelarGasService {
    uint256 public lastPaidGas;

    function payNativeGasForContractCall(
        address,
        string calldata,
        string calldata,
        bytes calldata,
        address
    ) external payable {
        lastPaidGas = msg.value;
    }

    function estimateGasFee(
        string calldata,
        string calldata,
        bytes calldata,
        uint256
    ) external pure returns (uint256) {
        return 0.001 ether;
    }
}

contract MockERC20Axelar is ERC20 {
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

contract AxelarBridgeAdapterTest is Test {
    AxelarBridgeAdapter public adapter;
    MockAxelarGateway public gateway;
    MockAxelarGasService public gasService;
    MockERC20Axelar public token;

    address public admin = address(0xAD);
    address public operator = address(0x0B);
    address public relayer = address(0xBE);
    address public user = address(0xDE);
    address public guardian = address(0xEF);

    string constant DEST_CHAIN = "avalanche";
    string constant DEST_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";

    function setUp() public {
        gateway = new MockAxelarGateway();
        gasService = new MockAxelarGasService();
        token = new MockERC20Axelar();

        adapter = new AxelarBridgeAdapter(
            address(gateway),
            address(gasService),
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
        adapter.grantRole(adapter.RELAYER_ROLE(), relayer);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);
        adapter.grantRole(adapter.PAUSER_ROLE(), admin);
        // Register a destination chain
        adapter.registerChain(DEST_CHAIN);
        vm.stopPrank();

        vm.deal(operator, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsGateway() public view {
        assertEq(address(adapter.axelarGateway()), address(gateway));
    }

    function test_constructor_setsGasService() public view {
        assertEq(address(adapter.axelarGasService()), address(gasService));
    }

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_setsDefaultGasLimit() public view {
        assertEq(adapter.executionGasLimit(), 300_000);
    }

    function test_constructor_revertsZeroGateway() public {
        vm.expectRevert(AxelarBridgeAdapter.InvalidGateway.selector);
        new AxelarBridgeAdapter(address(0), address(gasService), admin);
    }

    function test_constructor_revertsZeroGasService() public {
        vm.expectRevert(AxelarBridgeAdapter.InvalidGasService.selector);
        new AxelarBridgeAdapter(address(gateway), address(0), admin);
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert(AxelarBridgeAdapter.InvalidTarget.selector);
        new AxelarBridgeAdapter(
            address(gateway),
            address(gasService),
            address(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_constants() public view {
        assertEq(adapter.AXELAR_CHAIN_ID(), 12_100);
        assertEq(adapter.FINALITY_BLOCKS(), 28);
        assertEq(adapter.MIN_PROOF_SIZE(), 32);
        assertEq(adapter.MAX_BRIDGE_FEE_BPS(), 100);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 10_000);
        assertEq(adapter.DEFAULT_EXECUTION_GAS_LIMIT(), 300_000);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_chainId() public view {
        assertEq(adapter.chainId(), 12_100);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Axelar");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 28);
    }

    function test_isChainRegistered() public view {
        assertTrue(adapter.isChainRegistered(DEST_CHAIN));
        assertFalse(adapter.isChainRegistered("unknown"));
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setAxelarGateway() public {
        address newGateway = address(0x999);
        vm.prank(admin);
        adapter.setAxelarGateway(newGateway);
        assertEq(address(adapter.axelarGateway()), newGateway);
    }

    function test_setAxelarGateway_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AxelarBridgeAdapter.InvalidGateway.selector);
        adapter.setAxelarGateway(address(0));
    }

    function test_setAxelarGateway_revertsNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setAxelarGateway(address(0x999));
    }

    function test_setAxelarGasService() public {
        address newService = address(0x888);
        vm.prank(admin);
        adapter.setAxelarGasService(newService);
        assertEq(address(adapter.axelarGasService()), newService);
    }

    function test_setAxelarGasService_revertsZero() public {
        vm.prank(admin);
        vm.expectRevert(AxelarBridgeAdapter.InvalidGasService.selector);
        adapter.setAxelarGasService(address(0));
    }

    function test_registerChain() public {
        vm.prank(admin);
        adapter.registerChain("fantom");
        assertTrue(adapter.isChainRegistered("fantom"));
    }

    function test_registerChain_revertsEmpty() public {
        vm.prank(admin);
        vm.expectRevert(AxelarBridgeAdapter.InvalidChain.selector);
        adapter.registerChain("");
    }

    function test_unregisterChain() public {
        vm.prank(admin);
        adapter.unregisterChain(DEST_CHAIN);
        assertFalse(adapter.isChainRegistered(DEST_CHAIN));
    }

    function test_setBridgeFee() public {
        vm.prank(admin);
        adapter.setBridgeFee(50);
        assertEq(adapter.bridgeFee(), 50);
    }

    function test_setBridgeFee_revertsAboveMax() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(AxelarBridgeAdapter.FeeTooHigh.selector, 101)
        );
        adapter.setBridgeFee(101);
    }

    function test_setMinMessageFee() public {
        vm.prank(admin);
        adapter.setMinMessageFee(0.01 ether);
        assertEq(adapter.minMessageFee(), 0.01 ether);
    }

    function test_setExecutionGasLimit() public {
        vm.prank(admin);
        adapter.setExecutionGasLimit(500_000);
        assertEq(adapter.executionGasLimit(), 500_000);
    }

    /*//////////////////////////////////////////////////////////////
              SEND MESSAGE (ZASEON → Destination via Axelar)
    //////////////////////////////////////////////////////////////*/

    function test_sendMessage_success() public {
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"deadbeef"
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesSent(), 1);
        assertEq(adapter.totalValueBridged(), 0.01 ether);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"aa"
        );
        adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"bb"
        );
        vm.stopPrank();
        assertEq(adapter.senderNonces(operator), 2);
    }

    function test_sendMessage_revertsEmptyChain() public {
        vm.prank(operator);
        vm.expectRevert(AxelarBridgeAdapter.InvalidChain.selector);
        adapter.sendMessage{value: 0.01 ether}("", DEST_ADDRESS, hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyAddress() public {
        vm.prank(operator);
        vm.expectRevert(AxelarBridgeAdapter.InvalidTarget.selector);
        adapter.sendMessage{value: 0.01 ether}(DEST_CHAIN, "", hex"deadbeef");
    }

    function test_sendMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AxelarBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(DEST_CHAIN, DEST_ADDRESS, hex"");
    }

    function test_sendMessage_revertsPayloadTooLong() public {
        bytes memory longPayload = new bytes(10_001);
        vm.prank(operator);
        vm.expectRevert(AxelarBridgeAdapter.InvalidPayload.selector);
        adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            longPayload
        );
    }

    function test_sendMessage_revertsUnregisteredChain() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                AxelarBridgeAdapter.ChainNotRegistered.selector,
                "polygon"
            )
        );
        adapter.sendMessage{value: 0.01 ether}(
            "polygon",
            DEST_ADDRESS,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"deadbeef"
        );
    }

    function test_sendMessage_revertsWhenPaused() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.01 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"deadbeef"
        );
    }

    function test_sendMessage_accumulatesFees() public {
        vm.prank(admin);
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"beef"
        );

        // 0.5% of 1 ether = 0.005 ether
        assertEq(adapter.accumulatedFees(), 0.005 ether);
    }

    /*//////////////////////////////////////////////////////////////
            RECEIVE MESSAGE (Source → ZASEON via Axelar)
    //////////////////////////////////////////////////////////////*/

    function test_receiveMessage_success() public {
        bytes32 commandId = keccak256("cmd-1");
        bytes memory payload = abi.encodePacked(
            keccak256("nullifier-1"),
            hex"deadbeef"
        );

        vm.prank(relayer);
        bytes32 hash = adapter.receiveMessage(
            commandId,
            "ethereum",
            "0xsender",
            payload
        );
        assertTrue(hash != bytes32(0));
        assertEq(adapter.totalMessagesReceived(), 1);
        assertTrue(adapter.verifiedCommands(commandId));
    }

    function test_receiveMessage_revertsInvalidProof() public {
        gateway.setShouldApprove(false);
        bytes32 commandId = keccak256("cmd-2");

        vm.prank(relayer);
        vm.expectRevert(AxelarBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(commandId, "ethereum", "0xsender", hex"beef");
    }

    function test_receiveMessage_revertsDuplicateCommand() public {
        bytes32 commandId = keccak256("cmd-dup");
        bytes memory payload1 = abi.encodePacked(keccak256("null-1"), hex"aa");
        bytes memory payload2 = abi.encodePacked(keccak256("null-2"), hex"bb");

        vm.startPrank(relayer);
        adapter.receiveMessage(commandId, "ethereum", "0xsender", payload1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AxelarBridgeAdapter.CommandAlreadyExecuted.selector,
                commandId
            )
        );
        adapter.receiveMessage(commandId, "ethereum", "0xsender", payload2);
        vm.stopPrank();
    }

    function test_receiveMessage_revertsDuplicateNullifier() public {
        bytes32 nullifier = keccak256("shared-nullifier");
        bytes memory payload = abi.encodePacked(nullifier, hex"aa");

        vm.startPrank(relayer);
        adapter.receiveMessage(
            keccak256("cmd-a"),
            "ethereum",
            "0xsender",
            payload
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                AxelarBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveMessage(
            keccak256("cmd-b"),
            "ethereum",
            "0xsender",
            payload
        );
        vm.stopPrank();
    }

    function test_receiveMessage_revertsZeroCommandId() public {
        vm.prank(relayer);
        vm.expectRevert(AxelarBridgeAdapter.InvalidProof.selector);
        adapter.receiveMessage(bytes32(0), "ethereum", "0xsender", hex"beef");
    }

    function test_receiveMessage_revertsEmptyChain() public {
        vm.prank(relayer);
        vm.expectRevert(AxelarBridgeAdapter.InvalidChain.selector);
        adapter.receiveMessage(keccak256("cmd"), "", "0xsender", hex"beef");
    }

    function test_receiveMessage_revertsEmptyPayload() public {
        vm.prank(relayer);
        vm.expectRevert(AxelarBridgeAdapter.InvalidPayload.selector);
        adapter.receiveMessage(keccak256("cmd"), "ethereum", "0xsender", hex"");
    }

    function test_receiveMessage_revertsNonRelayer() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.receiveMessage(
            keccak256("cmd"),
            "ethereum",
            "0xsender",
            hex"beef"
        );
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
        vm.expectRevert(AxelarBridgeAdapter.InvalidTarget.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0),
            hex"deadbeef",
            address(0)
        );
    }

    function test_bridgeMessage_revertsEmptyPayload() public {
        vm.prank(operator);
        vm.expectRevert(AxelarBridgeAdapter.InvalidPayload.selector);
        adapter.bridgeMessage{value: 0.01 ether}(
            address(0xBEEF),
            hex"",
            address(0)
        );
    }

    function test_estimateFee() public view {
        uint256 fee = adapter.estimateFee(address(0xBEEF), hex"deadbeef");
        assertEq(fee, 0); // minMessageFee defaults to 0
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
        adapter.setBridgeFee(50); // 0.5%

        vm.prank(operator);
        adapter.sendMessage{value: 1 ether}(
            DEST_CHAIN,
            DEST_ADDRESS,
            hex"beef"
        );

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
            DEST_CHAIN,
            DEST_ADDRESS,
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
                    AxelarBridgeAdapter.FeeTooHigh.selector,
                    fee
                )
            );
            adapter.setBridgeFee(fee);
        }
    }

    function testFuzz_receiveMessage_uniqueCommands(
        bytes32 cmd1,
        bytes32 cmd2
    ) public {
        vm.assume(cmd1 != cmd2 && cmd1 != bytes32(0) && cmd2 != bytes32(0));
        bytes memory payload1 = abi.encodePacked(
            keccak256(abi.encode(cmd1)),
            hex"aa"
        );
        bytes memory payload2 = abi.encodePacked(
            keccak256(abi.encode(cmd2)),
            hex"bb"
        );

        vm.startPrank(relayer);
        adapter.receiveMessage(cmd1, "ethereum", "0xsender", payload1);
        adapter.receiveMessage(cmd2, "ethereum", "0xsender", payload2);
        vm.stopPrank();

        assertTrue(adapter.verifiedCommands(cmd1));
        assertTrue(adapter.verifiedCommands(cmd2));
        assertEq(adapter.totalMessagesReceived(), 2);
    }

    function testFuzz_setMinMessageFee(uint256 fee) public {
        vm.prank(admin);
        adapter.setMinMessageFee(fee);
        assertEq(adapter.minMessageFee(), fee);
    }
}
