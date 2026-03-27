// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/bridge/MultiBridgeRouter.sol";
import "../../contracts/crosschain/IBridgeAdapter.sol";

/// @dev Mock bridge adapter that accepts any call and returns a constant fee
contract MockBridgeAdapter is IBridgeAdapter {
    uint256 public constant FEE = 0.01 ether;

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        return keccak256(abi.encode(msg.sender, block.timestamp));
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return FEE;
    }

    function isMessageVerified(bytes32) external pure override returns (bool) {
        return true;
    }
}

contract MultiBridgeRouterFuzzTest is Test {
    MultiBridgeRouter public router;
    MockBridgeAdapter public adapterA;
    MockBridgeAdapter public adapterB;
    MockBridgeAdapter public adapterC;

    address admin = address(this);
    uint256 constant DEST_CHAIN = 42161; // Arbitrum

    IMultiBridgeRouter.BridgeType constant NATIVE =
        IMultiBridgeRouter.BridgeType.NATIVE_L2;
    IMultiBridgeRouter.BridgeType constant LZ =
        IMultiBridgeRouter.BridgeType.LAYERZERO;
    IMultiBridgeRouter.BridgeType constant HYPER =
        IMultiBridgeRouter.BridgeType.HYPERLANE;

    function setUp() public {
        router = new MultiBridgeRouter(admin);

        adapterA = new MockBridgeAdapter();
        adapterB = new MockBridgeAdapter();
        adapterC = new MockBridgeAdapter();

        // Register adapters with different security scores
        router.registerAdapter(NATIVE, address(adapterA), 90, 1000 ether);
        router.registerAdapter(LZ, address(adapterB), 80, 500 ether);
        router.registerAdapter(HYPER, address(adapterC), 70, 200 ether);

        // Add supported chains
        router.addSupportedChain(NATIVE, DEST_CHAIN);
        router.addSupportedChain(LZ, DEST_CHAIN);
        router.addSupportedChain(HYPER, DEST_CHAIN);

        // Set chain target for message routing
        router.setChainTarget(DEST_CHAIN, address(0xBEEF));

        // Register per-bridge operators (M-2 fix requires explicit operators)
        router.setBridgeOperator(NATIVE, address(this));
        router.setBridgeOperator(LZ, address(this));
        router.setBridgeOperator(HYPER, address(this));
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: registerAdapter security score
    //////////////////////////////////////////////////////////////*/

    /// @notice Scores > 100 must revert with InvalidSecurityScore; <= 100 must succeed
    function testFuzz_registerAdapter_securityScoreBounds(
        uint256 score
    ) public {
        MockBridgeAdapter newAdapter = new MockBridgeAdapter();

        if (score > 100) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IMultiBridgeRouter.InvalidSecurityScore.selector,
                    score
                )
            );
            router.registerAdapter(
                IMultiBridgeRouter.BridgeType.CHAINLINK_CCIP,
                address(newAdapter),
                score,
                100 ether
            );
        } else {
            router.registerAdapter(
                IMultiBridgeRouter.BridgeType.CHAINLINK_CCIP,
                address(newAdapter),
                score,
                100 ether
            );

            (address adapter, uint256 sec, , , , , , ) = router.bridges(
                IMultiBridgeRouter.BridgeType.CHAINLINK_CCIP
            );
            assertEq(adapter, address(newAdapter));
            assertEq(sec, score);
        }
    }

    /*//////////////////////////////////////////////////////////////
                   FUZZ: routeMessage value determinism
    //////////////////////////////////////////////////////////////*/

    /// @notice Same value must always select the same optimal bridge
    function testFuzz_routeMessage_valueDeterministic(uint256 value) public {
        value = bound(value, 0, 10_000 ether);

        IMultiBridgeRouter.BridgeType bridge1 = router.getOptimalBridge(
            DEST_CHAIN,
            value
        );
        IMultiBridgeRouter.BridgeType bridge2 = router.getOptimalBridge(
            DEST_CHAIN,
            value
        );

        assertEq(
            uint256(bridge1),
            uint256(bridge2),
            "Routing must be deterministic for same value"
        );
    }

    /*//////////////////////////////////////////////////////////////
               FUZZ: verifyMessage double-verify idempotency
    //////////////////////////////////////////////////////////////*/

    /// @notice Double-verifying same message with same bridge is idempotent
    function testFuzz_verifyMessage_doubleVerify(bytes32 msgId) public {
        // First verification from NATIVE bridge
        router.verifyMessage(msgId, NATIVE, true);

        // Second verification from same bridge — contract returns early (no-op)
        router.verifyMessage(msgId, NATIVE, true);

        // Only 1 unique confirmation so far; message should NOT be finalized
        bool verified = router.isMessageVerified(msgId);
        assertFalse(verified, "Single bridge double-verify must not finalize");

        // Second distinct bridge confirms — now reaches requiredConfirmations (2)
        router.verifyMessage(msgId, LZ, true);
        verified = router.isMessageVerified(msgId);
        assertTrue(verified, "Two distinct bridges should finalize");

        // Any further verification on a finalized message must revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiBridgeRouter.MessageAlreadyFinalized.selector,
                msgId
            )
        );
        router.verifyMessage(msgId, HYPER, true);
    }

    /*//////////////////////////////////////////////////////////////
                     FUZZ: thresholds ordering
    //////////////////////////////////////////////////////////////*/

    /// @notice updateThresholds accepts any values; verify storage is set correctly
    function testFuzz_thresholds_ordering(
        uint256 high,
        uint256 med,
        uint256 low
    ) public {
        high = bound(high, 0, type(uint128).max);
        med = bound(med, 0, type(uint128).max);
        low = bound(low, 0, type(uint128).max);

        router.updateThresholds(high, med, low);

        assertEq(router.highValueThreshold(), high);
        assertEq(router.mediumValueThreshold(), med);
        assertEq(router.multiVerificationThreshold(), low);
    }

    /*//////////////////////////////////////////////////////////////
                FUZZ: estimateFee non-zero for registered routes
    //////////////////////////////////////////////////////////////*/

    /// @notice Fee estimation returns non-zero for registered routes
    function testFuzz_estimateFee_nonZero(
        uint256 destChain,
        uint256 valueParam
    ) public {
        // Always use the registered destination chain
        destChain = DEST_CHAIN;
        valueParam = bound(valueParam, 0, 10_000 ether);

        IMultiBridgeRouter.BridgeType optimal = router.getOptimalBridge(
            destChain,
            valueParam
        );

        (address adapterAddr, , , , , , , ) = router.bridges(optimal);
        assertTrue(adapterAddr != address(0), "Adapter must be registered");

        bytes memory payload = abi.encode("test", valueParam);
        uint256 fee = IBridgeAdapter(adapterAddr).estimateFee(
            address(0xBEEF),
            payload
        );
        assertGt(fee, 0, "Fee must be non-zero for registered route");
    }
}
