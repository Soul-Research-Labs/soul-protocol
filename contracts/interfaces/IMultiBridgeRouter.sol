// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMultiBridgeRouter
 * @notice Interface for the MultiBridgeRouter cross-chain message routing contract
 * @dev Inherits: AccessControl, ReentrancyGuard, Pausable
 */
interface IMultiBridgeRouter {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum BridgeType {
        NATIVE_L2,
        LAYERZERO,
        HYPERLANE,
        CHAINLINK_CCIP,
        AXELAR
    }

    enum BridgeStatus {
        ACTIVE,
        DEGRADED,
        PAUSED,
        DISABLED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct BridgeConfig {
        address adapter;
        uint256 securityScore;
        uint256 maxValuePerTx;
        uint256 successCount;
        uint256 failureCount;
        uint256 lastFailureTime;
        BridgeStatus status;
        uint256 avgResponseTime;
    }

    /// @dev MessageVerification contains a mapping so cannot be returned externally.
    /// Use isMessageVerified() instead.

    struct RoutingDecision {
        BridgeType primaryBridge;
        BridgeType[] fallbackBridges;
        bool requireMultiVerification;
        uint256 minConfirmations;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeRegistered(BridgeType indexed bridgeType, address adapter);
    event BridgeStatusChanged(
        BridgeType indexed bridgeType,
        BridgeStatus oldStatus,
        BridgeStatus newStatus
    );
    event MessageRouted(
        bytes32 indexed messageHash,
        BridgeType primaryBridge,
        uint256 value
    );
    event MessageVerified(
        bytes32 indexed messageHash,
        BridgeType bridge,
        bool approved
    );
    event MessageFinalized(
        bytes32 indexed messageHash,
        bool approved,
        uint256 confirmations
    );
    event BridgeFallback(
        bytes32 indexed messageHash,
        BridgeType failedBridge,
        BridgeType fallbackBridge
    );
    event HealthCheckFailed(BridgeType indexed bridgeType, uint256 failureRate);
    event SupportedChainAdded(
        BridgeType indexed bridgeType,
        uint256 indexed chainId
    );
    event BridgeSuccessRecorded(
        BridgeType indexed bridgeType,
        uint256 newSuccessCount
    );
    event ThresholdsUpdated(
        uint256 highValueThreshold,
        uint256 mediumValueThreshold,
        uint256 multiVerificationThreshold
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error BridgeNotConfigured(BridgeType bridgeType);
    error BridgeNotActive(BridgeType bridgeType);
    error NoBridgeAvailable(uint256 chainId);
    error AllBridgesFailed(bytes32 messageHash);
    error InvalidSecurityScore(uint256 score);
    error ChainNotSupported(BridgeType bridgeType, uint256 chainId);
    error MessageAlreadyFinalized(bytes32 messageHash);
    error InsufficientConfirmations(uint256 current, uint256 required);

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function BRIDGE_ADMIN() external view returns (bytes32);

    function OPERATOR_ROLE() external view returns (bytes32);

    function MAX_FAILURE_RATE() external view returns (uint256);

    function DEGRADED_THRESHOLD() external view returns (uint256);

    function HEALTH_CHECK_WINDOW() external view returns (uint256);

    function bridges(
        BridgeType bridgeType
    )
        external
        view
        returns (
            address adapter,
            uint256 securityScore,
            uint256 maxValuePerTx,
            uint256 successCount,
            uint256 failureCount,
            uint256 lastFailureTime,
            BridgeStatus status,
            uint256 avgResponseTime
        );

    function supportedChains(
        BridgeType bridgeType,
        uint256 chainId
    ) external view returns (bool);

    function highValueThreshold() external view returns (uint256);

    function mediumValueThreshold() external view returns (uint256);

    function multiVerificationThreshold() external view returns (uint256);

    function requiredConfirmations() external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                        ROUTING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function routeMessage(
        uint256 destinationChainId,
        bytes calldata message,
        uint256 value
    ) external payable returns (bytes32 messageHash);

    function verifyMessage(
        bytes32 messageHash,
        BridgeType bridgeType,
        bool approved
    ) external;

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerBridge(
        BridgeType bridgeType,
        address adapter,
        uint256 securityScore,
        uint256 maxValuePerTx
    ) external;

    function updateBridgeStatus(
        BridgeType bridgeType,
        BridgeStatus newStatus
    ) external;

    function addSupportedChain(BridgeType bridgeType, uint256 chainId) external;

    function recordSuccess(BridgeType bridgeType) external;

    function recordFailure(BridgeType bridgeType) external;

    function updateThresholds(
        uint256 _highValueThreshold,
        uint256 _mediumValueThreshold,
        uint256 _multiVerificationThreshold
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getOptimalBridge(
        uint256 chainId,
        uint256 value
    ) external view returns (BridgeType bridgeType);

    function getBridgeHealth(
        BridgeType bridgeType
    ) external view returns (uint256 score);

    function isMessageVerified(
        bytes32 messageHash
    ) external view returns (bool verified);

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external;

    function unpause() external;
}
