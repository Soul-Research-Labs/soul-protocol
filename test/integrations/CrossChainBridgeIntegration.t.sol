// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/CrossChainBridgeIntegration.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock ERC20 for bridge tests
contract MockBridgeToken is ERC20 {
    constructor() ERC20("MockToken", "MTK") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Mock bridge adapter that accepts calls
contract MockBridgeAdapter {
    bool public shouldFail;
    uint256 public lastAmount;
    bytes32 public lastRecipient;

    function setShouldFail(bool _fail) external {
        shouldFail = _fail;
    }

    function bridge(
        uint256,
        bytes32 recipient,
        address,
        uint256 amount,
        bytes calldata
    ) external payable {
        if (shouldFail) revert("MockBridgeAdapter: fail");
        lastAmount = amount;
        lastRecipient = recipient;
    }

    receive() external payable {}
}

contract CrossChainBridgeIntegrationTest is Test {
    CrossChainBridgeIntegration public bridge;
    MockBridgeToken public token;
    MockBridgeAdapter public adapter;

    address public admin = address(this);
    address public feeRecipient = address(0xFEE);
    address public relayer = address(0xBEEF);
    address public user = address(0xCAFE);
    address public guardian = address(0xDEAD);

    uint256 public constant THIS_CHAIN = 1;
    uint256 public constant DEST_CHAIN = 42161; // Arbitrum
    uint256 public constant PROTOCOL_FEE_BPS = 50; // 0.5%

    // Cache to avoid external calls consuming vm.prank
    address public constant NATIVE =
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    function setUp() public {
        bridge = new CrossChainBridgeIntegration(
            THIS_CHAIN,
            feeRecipient,
            PROTOCOL_FEE_BPS
        );
        token = new MockBridgeToken();
        adapter = new MockBridgeAdapter();

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);

        // Fund accounts
        vm.deal(user, 100 ether);
        vm.deal(address(bridge), 100 ether);
        vm.deal(address(adapter), 10 ether);
        token.mint(user, 1000 ether);
        token.mint(address(bridge), 1000 ether);

        // Configure destination chain
        bridge.configureChain(
            DEST_CHAIN,
            CrossChainBridgeIntegration.ChainType.EVM,
            12, // minConfirmations
            100 ether, // maxTransfer
            500 ether // dailyLimit
        );

        // Register adapter
        bridge.registerBridgeAdapter(
            DEST_CHAIN,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            address(adapter),
            0.01 ether, // baseFee
            10 // 0.1% percentage fee
        );

        // Configure route
        CrossChainBridgeIntegration.BridgeProtocol[]
            memory protocols = new CrossChainBridgeIntegration.BridgeProtocol[](
                1
            );
        protocols[0] = CrossChainBridgeIntegration.BridgeProtocol.NATIVE;
        bridge.configureRoute(
            THIS_CHAIN,
            DEST_CHAIN,
            protocols,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
    }

    // ============= Constructor =============

    function test_Constructor_SetsChainId() public view {
        assertEq(bridge.THIS_CHAIN_ID(), THIS_CHAIN);
    }

    function test_Constructor_SetsFeeRecipient() public view {
        assertEq(bridge.feeRecipient(), feeRecipient);
    }

    function test_Constructor_SetsProtocolFee() public view {
        assertEq(bridge.protocolFeeBps(), PROTOCOL_FEE_BPS);
    }

    function test_Constructor_AutoRouterEnabled() public view {
        assertTrue(bridge.autoRouterEnabled());
    }

    function test_Constructor_RevertZeroFeeRecipient() public {
        vm.expectRevert(CrossChainBridgeIntegration.ZeroAddress.selector);
        new CrossChainBridgeIntegration(1, address(0), 50);
    }

    function test_Constructor_RevertExcessiveFee() public {
        vm.expectRevert(CrossChainBridgeIntegration.InvalidRoute.selector);
        new CrossChainBridgeIntegration(1, feeRecipient, 501);
    }

    // ============= Chain Management =============

    function test_ConfigureChain() public {
        bridge.configureChain(
            10,
            CrossChainBridgeIntegration.ChainType.EVM,
            6,
            50 ether,
            200 ether
        );
        CrossChainBridgeIntegration.ChainConfig memory cfg = bridge
            .getChainConfig(10);
        assertTrue(cfg.isSupported);
        assertEq(cfg.chainId, 10);
        assertEq(cfg.maxTransfer, 50 ether);
        assertEq(cfg.dailyLimit, 200 ether);
    }

    function test_ConfigureChain_RevertInvalidChainId() public {
        vm.expectRevert(CrossChainBridgeIntegration.InvalidChainId.selector);
        bridge.configureChain(
            0,
            CrossChainBridgeIntegration.ChainType.EVM,
            6,
            50 ether,
            200 ether
        );
    }

    function test_ConfigureChain_AddsSupportedChain() public {
        bridge.configureChain(
            10,
            CrossChainBridgeIntegration.ChainType.EVM,
            6,
            50 ether,
            200 ether
        );
        uint256[] memory chains = bridge.getSupportedChains();
        // DEST_CHAIN + chain 10
        assertEq(chains.length, 2);
    }

    function test_IsChainSupported() public view {
        assertTrue(bridge.isChainSupported(DEST_CHAIN));
        assertFalse(bridge.isChainSupported(999));
    }

    // ============= Bridge Adapter =============

    function test_RegisterBridgeAdapter() public {
        bridge.configureChain(
            10,
            CrossChainBridgeIntegration.ChainType.EVM,
            6,
            50 ether,
            200 ether
        );
        bridge.registerBridgeAdapter(
            10,
            CrossChainBridgeIntegration.BridgeProtocol.LAYERZERO,
            address(adapter),
            0.02 ether,
            20
        );
        CrossChainBridgeIntegration.BridgeAdapter memory ba = bridge
            .getBridgeAdapter(
                10,
                CrossChainBridgeIntegration.BridgeProtocol.LAYERZERO
            );
        assertTrue(ba.isActive);
        assertEq(ba.adapter, address(adapter));
        assertEq(ba.baseFee, 0.02 ether);
        assertEq(ba.reliability, 10000);
    }

    function test_RegisterBridgeAdapter_RevertZeroAddress() public {
        vm.expectRevert(CrossChainBridgeIntegration.ZeroAddress.selector);
        bridge.registerBridgeAdapter(
            DEST_CHAIN,
            CrossChainBridgeIntegration.BridgeProtocol.LAYERZERO,
            address(0),
            0,
            0
        );
    }

    function test_RegisterBridgeAdapter_RevertChainNotSupported() public {
        vm.expectRevert(CrossChainBridgeIntegration.ChainNotSupported.selector);
        bridge.registerBridgeAdapter(
            999,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            address(adapter),
            0,
            0
        );
    }

    // ============= Route Configuration =============

    function test_ConfigureRoute() public {
        CrossChainBridgeIntegration.BridgeProtocol[]
            memory protocols = new CrossChainBridgeIntegration.BridgeProtocol[](
                2
            );
        protocols[0] = CrossChainBridgeIntegration.BridgeProtocol.NATIVE;
        protocols[1] = CrossChainBridgeIntegration.BridgeProtocol.LAYERZERO;
        bridge.configureRoute(
            THIS_CHAIN,
            10,
            protocols,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
        CrossChainBridgeIntegration.Route memory route = bridge.getRoute(
            THIS_CHAIN,
            10
        );
        assertTrue(route.isActive);
        assertEq(route.availableProtocols.length, 2);
    }

    function test_ConfigureRoute_RevertEmpty() public {
        CrossChainBridgeIntegration.BridgeProtocol[]
            memory empty = new CrossChainBridgeIntegration.BridgeProtocol[](0);
        vm.expectRevert(CrossChainBridgeIntegration.InvalidRoute.selector);
        bridge.configureRoute(
            THIS_CHAIN,
            10,
            empty,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
    }

    function test_ConfigureRoute_RevertTooManyProtocols() public {
        CrossChainBridgeIntegration.BridgeProtocol[]
            memory tooMany = new CrossChainBridgeIntegration.BridgeProtocol[](
                6
            );
        vm.expectRevert(CrossChainBridgeIntegration.InvalidRoute.selector);
        bridge.configureRoute(
            THIS_CHAIN,
            10,
            tooMany,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
    }

    // ============= Bridge Transfer (Native Token) =============

    function test_BridgeTransfer_NativeToken() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));

        // Calculate fees: baseFee(0.01) + percentageFee(1*10/10000=0.001) + protocolFee(1*50/10000=0.005)
        uint256 amount = 1 ether;
        uint256 totalFee = 0.01 ether +
            (amount * 10) /
            10000 +
            (amount * PROTOCOL_FEE_BPS) /
            10000;

        vm.prank(user);
        bytes32 transferId = bridge.bridgeTransfer{value: amount + totalFee}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            amount,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        assertTrue(transferId != bytes32(0));
        CrossChainBridgeIntegration.TransferRecord memory record = bridge
            .getRelayRecord(transferId);
        assertEq(
            uint8(record.status),
            uint8(CrossChainBridgeIntegration.TransferStatus.PENDING)
        );
        assertEq(record.request.amount, amount);
    }

    function test_BridgeTransfer_RevertZeroRecipient() public {
        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.InvalidRecipient.selector);
        bridge.bridgeTransfer{value: 2 ether}(
            DEST_CHAIN,
            bytes32(0),
            NATIVE,
            1 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_RevertZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.ZeroAmount.selector);
        bridge.bridgeTransfer{value: 1 ether}(
            DEST_CHAIN,
            bytes32(uint256(1)),
            NATIVE,
            0,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_RevertChainNotSupported() public {
        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.ChainNotSupported.selector);
        bridge.bridgeTransfer{value: 2 ether}(
            999,
            bytes32(uint256(1)),
            NATIVE,
            1 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_RevertExceedsMaxTransfer() public {
        vm.deal(user, 200 ether);
        vm.prank(user);
        vm.expectRevert(
            CrossChainBridgeIntegration.ExceedsMaxTransfer.selector
        );
        bridge.bridgeTransfer{value: 150 ether}(
            DEST_CHAIN,
            bytes32(uint256(1)),
            NATIVE,
            101 ether, // max is 100
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_RevertExceedsDailyLimit() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));
        // Do multiple transfers to exhaust daily limit (500 ether)
        // Transfer 5 x 99 ether = 495, then 6th should fail
        vm.deal(user, 1000 ether);

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(user);
            bridge.bridgeTransfer{value: 100 ether}(
                DEST_CHAIN,
                recipient,
                NATIVE,
                99 ether,
                CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
                ""
            );
        }

        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.ExceedsDailyLimit.selector);
        bridge.bridgeTransfer{value: 10 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            6 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_DailyLimitResetsNextDay() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));
        vm.deal(user, 1000 ether);

        // Use 99 ether
        vm.prank(user);
        bridge.bridgeTransfer{value: 100 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            99 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        // Warp to next day
        vm.warp(block.timestamp + 1 days + 1);

        // Should succeed again
        vm.prank(user);
        bridge.bridgeTransfer{value: 100 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            99 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    function test_BridgeTransfer_TracksUserTransfers() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));

        vm.prank(user);
        bridge.bridgeTransfer{value: 2 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            1 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        bytes32[] memory userTx = bridge.getUserTransfers(user);
        assertEq(userTx.length, 1);
    }

    function test_BridgeTransfer_AccruesProtocolFees() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));
        uint256 amount = 10 ether;
        uint256 expectedProtocolFee = (amount * PROTOCOL_FEE_BPS) / 10000;

        vm.prank(user);
        bridge.bridgeTransfer{value: 15 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            amount,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        assertEq(bridge.accruedProtocolFees(), expectedProtocolFee);
    }

    // ============= Bridge Transfer (ERC20) =============

    function test_BridgeTransfer_ERC20() public {
        bytes32 recipient = bytes32(uint256(uint160(user)));
        uint256 amount = 10 ether;

        // Calculate fee
        uint256 bridgeFee = 0.01 ether + (amount * 10) / 10000;
        uint256 protocolFee = (amount * PROTOCOL_FEE_BPS) / 10000;
        uint256 totalFee = bridgeFee + protocolFee;

        vm.startPrank(user);
        token.approve(address(bridge), amount);
        bridge.bridgeTransfer{value: totalFee}(
            DEST_CHAIN,
            recipient,
            address(token),
            amount,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
        vm.stopPrank();

        // Token should be transferred from user
        assertEq(token.balanceOf(address(bridge)), 1000 ether + amount);
    }

    // ============= Complete Transfer =============

    function test_CompleteTransfer_NativeToken() public {
        bytes32 transferId = keccak256("transfer1");
        bytes32 recipient = bytes32(uint256(uint160(user)));
        uint256 amount = 1 ether;

        // Create valid signature from relayer
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        transferId,
                        recipient,
                        NATIVE,
                        amount,
                        block.chainid
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            uint256(uint160(relayer)),
            messageHash
        );
        // Need a proper private key. Use vm.addr pattern
        uint256 relayerPk = 0xBEEF;
        address relayerAddr = vm.addr(relayerPk);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayerAddr);

        messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        transferId,
                        recipient,
                        NATIVE,
                        amount,
                        block.chainid
                    )
                )
            )
        );
        (v, r, s) = vm.sign(relayerPk, messageHash);
        bytes memory proof = abi.encodePacked(r, s, v);

        uint256 userBalBefore = user.balance;
        vm.prank(relayerAddr);
        bridge.completeRelay(transferId, recipient, NATIVE, amount, proof);

        assertEq(user.balance - userBalBefore, amount);
    }

    function test_CompleteTransfer_RevertAlreadyProcessed() public {
        bytes32 transferId = keccak256("transfer1");
        bytes32 recipient = bytes32(uint256(uint160(user)));
        uint256 amount = 1 ether;

        uint256 relayerPk = 0xBEEF;
        address relayerAddr = vm.addr(relayerPk);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayerAddr);

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        transferId,
                        recipient,
                        NATIVE,
                        amount,
                        block.chainid
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPk, messageHash);
        bytes memory proof = abi.encodePacked(r, s, v);

        vm.prank(relayerAddr);
        bridge.completeRelay(transferId, recipient, NATIVE, amount, proof);

        vm.prank(relayerAddr);
        vm.expectRevert(
            CrossChainBridgeIntegration.MessageAlreadyProcessed.selector
        );
        bridge.completeRelay(transferId, recipient, NATIVE, amount, proof);
    }

    function test_CompleteTransfer_RevertInvalidProof() public {
        bytes32 transferId = keccak256("transfer1");
        bytes32 recipient = bytes32(uint256(uint160(user)));

        // Sign with non-relayer key
        uint256 nonRelayerPk = 0xDEAD;

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        transferId,
                        recipient,
                        NATIVE,
                        uint256(1 ether)
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonRelayerPk, messageHash);
        bytes memory proof = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        vm.expectRevert(CrossChainBridgeIntegration.InvalidProof.selector);
        bridge.completeRelay(transferId, recipient, NATIVE, 1 ether, proof);
    }

    // ============= Quote =============

    function test_GetQuote() public view {
        (uint256 bridgeFee, uint256 protocolFee, ) = bridge.getQuote(
            DEST_CHAIN,
            address(token),
            10 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );

        // baseFee=0.01 + 10e18 * 10/10000 = 0.01 + 0.01 = 0.02
        assertEq(bridgeFee, 0.01 ether + (10 ether * 10) / 10000);
        // protocolFee = 10 * 50 / 10000 = 0.05
        assertEq(protocolFee, (10 ether * PROTOCOL_FEE_BPS) / 10000);
    }

    function test_GetQuote_RevertBridgeNotAvailable() public {
        bridge.setAutoRouter(false);
        vm.expectRevert(
            CrossChainBridgeIntegration.BridgeNotAvailable.selector
        );
        bridge.getQuote(
            DEST_CHAIN,
            address(token),
            10 ether,
            CrossChainBridgeIntegration.BridgeProtocol.LAYERZERO
        );
    }

    // ============= Claim Protocol Fees =============

    function test_ClaimProtocolFees() public {
        // Generate some protocol fees
        bytes32 recipient = bytes32(uint256(uint160(user)));
        vm.prank(user);
        bridge.bridgeTransfer{value: 15 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            10 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        uint256 fees = bridge.accruedProtocolFees();
        assertGt(fees, 0);

        uint256 balBefore = feeRecipient.balance;
        vm.deal(address(bridge), fees + 1 ether); // ensure bridge has funds
        vm.prank(feeRecipient);
        bridge.claimProtocolFees();
        assertEq(feeRecipient.balance - balBefore, fees);
        assertEq(bridge.accruedProtocolFees(), 0);
    }

    function test_ClaimProtocolFees_RevertUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.Unauthorized.selector);
        bridge.claimProtocolFees();
    }

    // ============= Admin Functions =============

    function test_SetAutoRouter() public {
        bridge.setAutoRouter(false);
        assertFalse(bridge.autoRouterEnabled());
        bridge.setAutoRouter(true);
        assertTrue(bridge.autoRouterEnabled());
    }

    function test_SetFeeRecipient() public {
        address newRecipient = address(0x123);
        bridge.setFeeRecipient(newRecipient);
        assertEq(bridge.feeRecipient(), newRecipient);
    }

    function test_SetFeeRecipient_RevertZeroAddress() public {
        vm.expectRevert(CrossChainBridgeIntegration.ZeroAddress.selector);
        bridge.setFeeRecipient(address(0));
    }

    function test_SetProtocolFee() public {
        bridge.setProtocolFee(100);
        assertEq(bridge.protocolFeeBps(), 100);
    }

    function test_SetProtocolFee_RevertExcessive() public {
        vm.expectRevert(CrossChainBridgeIntegration.InvalidRoute.selector);
        bridge.setProtocolFee(501);
    }

    function test_UpdateAdapterMetrics() public {
        bridge.updateAdapterMetrics(
            DEST_CHAIN,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            100,
            9500
        );
        CrossChainBridgeIntegration.BridgeAdapter memory ba = bridge
            .getBridgeAdapter(
                DEST_CHAIN,
                CrossChainBridgeIntegration.BridgeProtocol.NATIVE
            );
        assertEq(ba.avgLatency, 100);
        assertEq(ba.reliability, 9500);
    }

    function test_DeactivateAdapter() public {
        vm.prank(guardian);
        bridge.deactivateAdapter(
            DEST_CHAIN,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
        CrossChainBridgeIntegration.BridgeAdapter memory ba = bridge
            .getBridgeAdapter(
                DEST_CHAIN,
                CrossChainBridgeIntegration.BridgeProtocol.NATIVE
            );
        assertFalse(ba.isActive);
    }

    function test_Pause_Unpause() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.bridgeTransfer{value: 2 ether}(
            DEST_CHAIN,
            bytes32(uint256(1)),
            NATIVE,
            1 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );

        bridge.unpause();
    }

    function test_EmergencyWithdraw_ETH() public {
        address recipient = address(0x999);
        uint256 bridgeBal = address(bridge).balance;
        bridge.emergencyWithdraw(NATIVE, recipient);
        assertEq(recipient.balance, bridgeBal);
    }

    function test_EmergencyWithdraw_ERC20() public {
        address recipient = address(0x999);
        uint256 tokenBal = token.balanceOf(address(bridge));
        bridge.emergencyWithdraw(address(token), recipient);
        assertEq(token.balanceOf(recipient), tokenBal);
    }

    function test_EmergencyWithdraw_RevertZeroAddress() public {
        vm.expectRevert(CrossChainBridgeIntegration.ZeroAddress.selector);
        bridge.emergencyWithdraw(NATIVE, address(0));
    }

    // ============= View Functions =============

    function test_GetSupportedChains() public view {
        uint256[] memory chains = bridge.getSupportedChains();
        assertEq(chains.length, 1);
        assertEq(chains[0], DEST_CHAIN);
    }

    // ============= Bridge Call Failure =============

    function test_BridgeTransfer_RevertBridgeCallFailed() public {
        adapter.setShouldFail(true);
        bytes32 recipient = bytes32(uint256(uint160(user)));

        vm.prank(user);
        vm.expectRevert(CrossChainBridgeIntegration.BridgeCallFailed.selector);
        bridge.bridgeTransfer{value: 5 ether}(
            DEST_CHAIN,
            recipient,
            NATIVE,
            1 ether,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE,
            ""
        );
    }

    // ============= Fuzz Tests =============

    function testFuzz_ProtocolFee_Calculation(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 100 ether);
        (, uint256 protocolFee, ) = bridge.getQuote(
            DEST_CHAIN,
            NATIVE,
            amount,
            CrossChainBridgeIntegration.BridgeProtocol.NATIVE
        );
        assertEq(protocolFee, (amount * PROTOCOL_FEE_BPS) / 10000);
    }

    function testFuzz_SetProtocolFee_BoundedAt500(uint256 feeBps) public {
        if (feeBps > 500) {
            vm.expectRevert(CrossChainBridgeIntegration.InvalidRoute.selector);
            bridge.setProtocolFee(feeBps);
        } else {
            bridge.setProtocolFee(feeBps);
            assertEq(bridge.protocolFeeBps(), feeBps);
        }
    }

    // ============= Receive ETH =============

    function test_ReceiveETH() public {
        uint256 balBefore = address(bridge).balance;
        (bool ok, ) = address(bridge).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(bridge).balance, balBefore + 1 ether);
    }
}
