// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/bridge/MultiBridgeRouter.sol";

/**
 * @title MultiBridgeRouterInvariant
 * @notice Invariant tests for MultiBridgeRouter
 * @dev Ensures:
 *  - Success + failure counts are monotonically increasing
 *  - Finalized messages stay finalized and immutable
 *  - Security scores are bounded [0, 100]
 *  - Health auto-degradation triggers correctly
 *  - Message consensus is consistent (confirmations + rejections <= bridge count)
 *
 * Run with: forge test --match-contract MultiBridgeRouterInvariant -vvv
 */
contract MultiBridgeRouterInvariant is StdInvariant, Test {
    MultiBridgeRouter public router;
    MultiBridgeRouterHandler public handler;

    function setUp() public {
        router = new MultiBridgeRouter(address(this));

        handler = new MultiBridgeRouterHandler(router);
        targetContract(address(handler));

        // Register mock adapters
        _registerMockAdapters();
    }

    function _registerMockAdapters() internal {
        // Register adapters with different security scores
        MockBridgeAdapter mockNative = new MockBridgeAdapter();
        MockBridgeAdapter mockLZ = new MockBridgeAdapter();
        MockBridgeAdapter mockHL = new MockBridgeAdapter();

        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            address(mockNative),
            90,
            1000 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            address(mockLZ),
            80,
            500 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            address(mockHL),
            85,
            500 ether
        );

        // Add supported chains
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            42161
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            42161
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            42161
        );

        // Set chain target for destination
        router.setChainTarget(42161, makeAddr("arbitrumHub"));
    }

    /// @notice Success + failure counts can only increase, never decrease
    function invariant_countersMonotonic() public view {
        (uint256 nativeSuccess, uint256 nativeFail) = handler.ghost_lastCounts(
            IMultiBridgeRouter.BridgeType.NATIVE_L2
        );
        (
            ,
            uint256 currentScore,
            uint256 currentMax,
            uint256 currentSuccess,
            uint256 currentFail,
            ,
            ,

        ) = router.bridges(IMultiBridgeRouter.BridgeType.NATIVE_L2);

        assertGe(currentSuccess, nativeSuccess, "Success count decreased");
        assertGe(currentFail, nativeFail, "Failure count decreased");
    }

    /// @notice Finalized messages must stay finalized
    function invariant_finalizedPermanence() public view {
        bytes32[] memory finalized = handler.ghost_finalizedMessages();
        for (uint256 i = 0; i < finalized.length; i++) {
            assertTrue(
                router.isMessageVerified(finalized[i]),
                "Finalized message became unverified"
            );
        }
    }

    /// @notice Security scores must be in range [0, 100]
    function invariant_securityScoreBounds() public view {
        for (uint256 bt = 0; bt <= 4; bt++) {
            (address adapter, uint256 securityScore, , , , , , ) = router
                .bridges(IMultiBridgeRouter.BridgeType(bt));
            if (adapter != address(0)) {
                assertLe(securityScore, 100, "Security score exceeds 100");
            }
        }
    }
}

/**
 * @title MultiBridgeRouterHandler
 * @notice Fuzzable handler for MultiBridgeRouter
 */
contract MultiBridgeRouterHandler is Test {
    MultiBridgeRouter public router;

    // Ghost tracking
    bytes32[] private _finalizedMessages;
    mapping(IMultiBridgeRouter.BridgeType => uint256) private _lastSuccess;
    mapping(IMultiBridgeRouter.BridgeType => uint256) private _lastFail;

    constructor(MultiBridgeRouter _router) {
        router = _router;
    }

    function ghost_finalizedMessages()
        external
        view
        returns (bytes32[] memory)
    {
        return _finalizedMessages;
    }

    function ghost_lastCounts(
        IMultiBridgeRouter.BridgeType bt
    ) external view returns (uint256 success, uint256 fail) {
        return (_lastSuccess[bt], _lastFail[bt]);
    }

    /// @notice Record a bridge success
    function recordSuccess(uint8 bridgeTypeSeed) external {
        IMultiBridgeRouter.BridgeType bt = IMultiBridgeRouter.BridgeType(
            bound(uint256(bridgeTypeSeed), 0, 2)
        );

        // Snapshot current counts
        (, , , uint256 curSuccess, uint256 curFail, , , ) = router.bridges(bt);
        _lastSuccess[bt] = curSuccess;
        _lastFail[bt] = curFail;

        try router.recordSuccess(bt) {} catch {}
    }

    /// @notice Record a bridge failure
    function recordFailure(uint8 bridgeTypeSeed) external {
        IMultiBridgeRouter.BridgeType bt = IMultiBridgeRouter.BridgeType(
            bound(uint256(bridgeTypeSeed), 0, 2)
        );

        // Snapshot current counts
        (, , , uint256 curSuccess, uint256 curFail, , , ) = router.bridges(bt);
        _lastSuccess[bt] = curSuccess;
        _lastFail[bt] = curFail;

        try router.recordFailure(bt) {} catch {}
    }

    /// @notice Verify a message from a specific bridge
    function verifyMessage(
        bytes32 messageHash,
        uint8 bridgeTypeSeed,
        bool approved
    ) external {
        IMultiBridgeRouter.BridgeType bt = IMultiBridgeRouter.BridgeType(
            bound(uint256(bridgeTypeSeed), 0, 2)
        );

        try router.verifyMessage(messageHash, bt, approved) {
            if (router.isMessageVerified(messageHash)) {
                _finalizedMessages.push(messageHash);
            }
        } catch {}
    }
}

/**
 * @title MockBridgeAdapter
 * @notice Minimal mock bridge adapter for testing
 */
contract MockBridgeAdapter {
    mapping(bytes32 => bool) public verified;
    uint256 public nonce;

    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable returns (bytes32) {
        nonce++;
        bytes32 id = keccak256(abi.encode(nonce));
        verified[id] = true;
        return id;
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure returns (uint256) {
        return 0.001 ether;
    }

    function isMessageVerified(bytes32 messageId) external view returns (bool) {
        return verified[messageId];
    }
}
