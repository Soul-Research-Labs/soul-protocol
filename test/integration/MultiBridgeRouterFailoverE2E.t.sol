// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MultiBridgeRouter} from "../../contracts/bridge/MultiBridgeRouter.sol";
import {IMultiBridgeRouter} from "../../contracts/interfaces/IMultiBridgeRouter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";

/// @dev Mock bridge adapter implementing IBridgeAdapter that can be toggled to succeed or fail
contract MockBridgeAdapter is IBridgeAdapter {
    bool public shouldFail;
    uint256 public callCount;
    bytes public lastMessage;

    function setShouldFail(bool _fail) external {
        shouldFail = _fail;
    }

    function bridgeMessage(
        address,
        bytes calldata payload,
        address
    ) external payable override returns (bytes32 messageId) {
        if (shouldFail) revert("MockBridgeAdapter: forced failure");
        callCount++;
        lastMessage = payload;
        return keccak256(abi.encodePacked(callCount, payload));
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256 nativeFee) {
        return 0.001 ether;
    }

    function isMessageVerified(bytes32) external pure override returns (bool) {
        return true;
    }
}

/**
 * @title MultiBridgeRouterFailoverE2E
 * @notice E2E test for MultiBridgeRouter failover behavior:
 *         primary → degraded fallback → tertiary fallback
 *         + multi-bridge consensus verification
 * @dev Validates:
 *      1. Messages route through optimal (highest security score) bridge
 *      2. On primary bridge failure, router falls back to next best bridge
 *      3. Multi-bridge verification reaches consensus
 *      4. All-bridge-failure reverts cleanly
 *      5. Bridge health tracking after failures
 */
contract MultiBridgeRouterFailoverE2E is Test {
    MultiBridgeRouter public router;
    MockBridgeAdapter public nativeAdapter;
    MockBridgeAdapter public layerZeroAdapter;
    MockBridgeAdapter public hyperlaneAdapter;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public user = makeAddr("user");

    bytes32 public constant BRIDGE_ADMIN = keccak256("BRIDGE_ADMIN");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    uint256 public constant ARBITRUM_CHAIN_ID = 42161;

    function setUp() public {
        // Deploy router
        vm.startPrank(admin);
        router = new MultiBridgeRouter(admin);
        router.grantRole(OPERATOR_ROLE, operator);

        // Deploy mock adapters
        nativeAdapter = new MockBridgeAdapter();
        layerZeroAdapter = new MockBridgeAdapter();
        hyperlaneAdapter = new MockBridgeAdapter();

        // Register adapters with different security scores
        // Native: highest security (95), LayerZero: medium (80), Hyperlane: lower (70)
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            address(nativeAdapter),
            95,
            1000 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            address(layerZeroAdapter),
            80,
            500 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            address(hyperlaneAdapter),
            70,
            500 ether
        );

        // Add supported chain
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            ARBITRUM_CHAIN_ID
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            ARBITRUM_CHAIN_ID
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            ARBITRUM_CHAIN_ID
        );

        // Set chain target for destination chain
        router.setChainTarget(ARBITRUM_CHAIN_ID, makeAddr("arbitrumHub"));

        vm.stopPrank();
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Normal routing through primary bridge
    // ═════════════════════════════════════════════════════════════

    function test_E2E_NormalRoutingPrimaryBridge() public {
        bytes memory message = abi.encodePacked("test-payload");

        // Use high value (>= 100 ether) to trigger _getMostSecureBridge path
        // which picks native adapter (score 95, highest)
        vm.prank(user);
        bytes32 msgHash = router.routeMessage(
            ARBITRUM_CHAIN_ID,
            message,
            100 ether
        );

        assertTrue(msgHash != bytes32(0), "Should return valid message hash");
        // Most-secure (native) should be called for high-value transfers
        assertGt(
            nativeAdapter.callCount(),
            0,
            "Native adapter should be called for high-value routing"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Failover from primary to fallback
    // ═════════════════════════════════════════════════════════════

    function test_E2E_FailoverToSecondaryBridge() public {
        // Make primary bridge fail
        nativeAdapter.setShouldFail(true);

        bytes memory message = abi.encodePacked("failover-payload");

        vm.prank(user);
        bytes32 msgHash = router.routeMessage(
            ARBITRUM_CHAIN_ID,
            message,
            1 ether
        );

        assertTrue(msgHash != bytes32(0), "Should return valid message hash");
        // Native failed, so fallback bridges should be tried
        assertGt(
            layerZeroAdapter.callCount() + hyperlaneAdapter.callCount(),
            0,
            "Fallback adapter should be called"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: All bridges fail → revert
    // ═════════════════════════════════════════════════════════════

    function test_E2E_AllBridgesFailReverts() public {
        // Make all bridges fail
        nativeAdapter.setShouldFail(true);
        layerZeroAdapter.setShouldFail(true);
        hyperlaneAdapter.setShouldFail(true);

        bytes memory message = abi.encodePacked("all-fail-payload");

        vm.prank(user);
        vm.expectRevert(); // AllBridgesFailed
        router.routeMessage(ARBITRUM_CHAIN_ID, message, 1 ether);
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Multi-bridge verification consensus
    // ═════════════════════════════════════════════════════════════

    function test_E2E_MultiBridgeVerificationConsensus() public {
        bytes memory message = abi.encodePacked("consensus-payload");

        vm.prank(user);
        bytes32 msgHash = router.routeMessage(
            ARBITRUM_CHAIN_ID,
            message,
            100 ether
        );

        // Submit verifications from multiple bridges
        vm.startPrank(operator);

        // First verification — not yet finalized
        router.verifyMessage(
            msgHash,
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            true
        );

        // Second verification — should reach consensus (requiredConfirmations = 2)
        router.verifyMessage(
            msgHash,
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            true
        );

        vm.stopPrank();

        // Message should now be verified
        assertTrue(
            router.isMessageVerified(msgHash),
            "Message should be verified after 2 confirmations"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Bridge health tracking after failures
    // ═════════════════════════════════════════════════════════════

    function test_E2E_BridgeHealthDegradation() public {
        // Record failures on native bridge
        vm.startPrank(operator);
        router.recordFailure(IMultiBridgeRouter.BridgeType.NATIVE_L2);
        router.recordFailure(IMultiBridgeRouter.BridgeType.NATIVE_L2);
        router.recordFailure(IMultiBridgeRouter.BridgeType.NATIVE_L2);
        vm.stopPrank();

        // Check bridge health
        uint256 healthScore = router.getBridgeHealth(
            IMultiBridgeRouter.BridgeType.NATIVE_L2
        );

        // After failures, health score should be reduced
        assertTrue(healthScore < 100, "Bridge health should reflect failures");
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Paused router blocks messages
    // ═════════════════════════════════════════════════════════════

    function test_E2E_PausedRouterBlocksMessages() public {
        vm.prank(admin);
        router.pause();

        bytes memory message = abi.encodePacked("paused-payload");

        vm.prank(user);
        vm.expectRevert(); // EnforcedPause
        router.routeMessage(ARBITRUM_CHAIN_ID, message, 1 ether);
    }
}
