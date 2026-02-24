// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../crosschain/IBridgeAdapter.sol";
import "../interfaces/IMultiBridgeRouter.sol";

/**
 * @title MultiBridgeRouter
 * @author Soul Protocol
 * @notice Routes cross-chain messages through multiple bridge providers for redundancy
 * @dev Implements:
 *      - Multi-bridge verification (2-of-3 consensus)
 *      - Automatic fallback on bridge failure
 *      - Bridge health monitoring
 *      - Value-based routing (high value = more secure bridge)
 *
 * ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    MULTI-BRIDGE ROUTER                                 │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
 * │  │ Native L2   │  │ LayerZero   │  │ Hyperlane   │  │ Chainlink   │  │
 * │  │ Bridge      │  │ V2          │  │             │  │ CCIP        │  │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
 * │         │                │                │                │          │
 * │         └────────────────┼────────────────┼────────────────┘          │
 * │                          │                │                            │
 * │                ┌─────────▼────────────────▼─────────┐                 │
 * │                │   Bridge Selection Logic           │                 │
 * │                │   - Value-based routing            │                 │
 * │                │   - Health-based selection         │                 │
 * │                │   - Fallback cascade               │                 │
 * │                └─────────┬──────────────────────────┘                 │
 * │                          │                                            │
 * │                ┌─────────▼─────────┐                                  │
 * │                │  Multi-Verification│                                 │
 * │                │  (2-of-3 consensus)│                                 │
 * │                └────────────────────┘                                 │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract MultiBridgeRouter is
    IMultiBridgeRouter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant BRIDGE_ADMIN = keccak256("BRIDGE_ADMIN");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    // BridgeType, BridgeStatus, BridgeConfig, RoutingDecision inherited from IMultiBridgeRouter

    struct MessageVerification {
        bytes32 messageHash;
        uint256 confirmations;
        uint256 rejections;
        mapping(BridgeType => bool) verified;
        bool finalized;
        bool approved;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configurations
    mapping(BridgeType => BridgeConfig) public bridges;

    /// @notice Message verifications for multi-bridge consensus
    mapping(bytes32 => MessageVerification) internal _verifications;

    /// @notice Supported chains per bridge
    mapping(BridgeType => mapping(uint256 => bool)) public supportedChains;

    /// @notice Value thresholds for routing
    uint256 public highValueThreshold = 100 ether;
    uint256 public mediumValueThreshold = 10 ether;

    /// @notice Multi-verification settings
    uint256 public multiVerificationThreshold = 50 ether;
    uint256 public requiredConfirmations = 2;

    /// @notice Health check parameters
    uint256 public constant MAX_FAILURE_RATE = 500; // 5% in basis points
    uint256 public constant DEGRADED_THRESHOLD = 1000; // 10%
    uint256 public constant HEALTH_CHECK_WINDOW = 1 hours;

    // Events and errors inherited from IMultiBridgeRouter:
    // BridgeRegistered, BridgeStatusChanged, MessageRouted, MessageVerified, MessageFinalized,
    // BridgeFallback, HealthCheckFailed, SupportedChainAdded, BridgeSuccessRecorded, ThresholdsUpdated,
    // BridgeNotConfigured, BridgeNotActive, NoBridgeAvailable, AllBridgesFailed,
    // InvalidSecurityScore, ChainNotSupported, MessageAlreadyFinalized, InsufficientConfirmations

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(BRIDGE_ADMIN, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                          ROUTING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Route a message through the optimal bridge
     * @param destinationChainId Target chain
     * @param message Message payload
     * @param value Value being transferred
     * @return messageHash Unique message identifier
     */
    function routeMessage(
        uint256 destinationChainId,
        bytes calldata message,
        uint256 value
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        messageHash = keccak256(
            abi.encode(message, block.timestamp, msg.sender)
        );

        // Determine routing strategy
        RoutingDecision memory decision = _determineRouting(
            destinationChainId,
            value
        );

        // Try primary bridge
        bool success = _sendViaBridge(
            decision.primaryBridge,
            destinationChainId,
            message,
            messageHash
        );

        if (!success) {
            // Try fallback bridges
            success = _tryFallbacks(
                decision.fallbackBridges,
                destinationChainId,
                message,
                messageHash
            );

            if (!success) {
                revert AllBridgesFailed(messageHash);
            }
        }

        emit MessageRouted(messageHash, decision.primaryBridge, value);

        // Initialize multi-verification if required
        if (decision.requireMultiVerification) {
            MessageVerification storage verification = _verifications[
                messageHash
            ];
            verification.messageHash = messageHash;
        }
    }

    /**
     * @notice Verify a message from a bridge (for multi-bridge consensus)
     * @param messageHash Message to verify
     * @param bridgeType Bridge reporting verification
     * @param approved Whether bridge approves the message
     */
    function verifyMessage(
        bytes32 messageHash,
        BridgeType bridgeType,
        bool approved
    ) external onlyRole(OPERATOR_ROLE) {
        MessageVerification storage verification = _verifications[messageHash];

        if (verification.messageHash == bytes32(0)) {
            // Initialize if first verification
            verification.messageHash = messageHash;
        }

        if (verification.finalized) {
            revert MessageAlreadyFinalized(messageHash);
        }

        if (verification.verified[bridgeType]) {
            return; // Already verified by this bridge
        }

        verification.verified[bridgeType] = true;

        if (approved) {
            verification.confirmations++;
        } else {
            verification.rejections++;
        }

        emit MessageVerified(messageHash, bridgeType, approved);

        // Check if we can finalize
        if (verification.confirmations >= requiredConfirmations) {
            verification.finalized = true;
            verification.approved = true;
            emit MessageFinalized(
                messageHash,
                true,
                verification.confirmations
            );
        } else if (verification.rejections >= requiredConfirmations) {
            verification.finalized = true;
            verification.approved = false;
            emit MessageFinalized(messageHash, false, verification.rejections);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register or update a bridge
     * @param bridgeType Type of bridge
     * @param adapter Bridge adapter contract
     * @param securityScore Security score (0-100)
     * @param maxValuePerTx Maximum value per transaction
     */
    function registerBridge(
        BridgeType bridgeType,
        address adapter,
        uint256 securityScore,
        uint256 maxValuePerTx
    ) external onlyRole(BRIDGE_ADMIN) {
        if (adapter == address(0)) revert ZeroAddress();
        if (securityScore > 100) revert InvalidSecurityScore(securityScore);

        bridges[bridgeType] = BridgeConfig({
            adapter: adapter,
            securityScore: securityScore,
            maxValuePerTx: maxValuePerTx,
            successCount: 0,
            failureCount: 0,
            lastFailureTime: 0,
            status: BridgeStatus.ACTIVE,
            avgResponseTime: 0
        });

        emit BridgeRegistered(bridgeType, adapter);
    }

    /**
     * @notice Update bridge status
     * @param bridgeType Bridge to update
     * @param newStatus New status
     */
    function updateBridgeStatus(
        BridgeType bridgeType,
        BridgeStatus newStatus
    ) external onlyRole(BRIDGE_ADMIN) {
        BridgeConfig storage bridge = bridges[bridgeType];
        BridgeStatus oldStatus = bridge.status;
        bridge.status = newStatus;

        emit BridgeStatusChanged(bridgeType, oldStatus, newStatus);
    }

    /**
     * @notice Add supported chain for a bridge
     * @param bridgeType Bridge type
     * @param chainId Chain to support
     */
    function addSupportedChain(
        BridgeType bridgeType,
        uint256 chainId
    ) external onlyRole(BRIDGE_ADMIN) {
        supportedChains[bridgeType][chainId] = true;
        emit SupportedChainAdded(bridgeType, chainId);
    }

    /**
     * @notice Record bridge success
     * @param bridgeType Bridge that succeeded
     */
    function recordSuccess(
        BridgeType bridgeType
    ) external onlyRole(OPERATOR_ROLE) {
        bridges[bridgeType].successCount++;
        emit BridgeSuccessRecorded(
            bridgeType,
            bridges[bridgeType].successCount
        );
    }

    /**
     * @notice Record bridge failure
     * @param bridgeType Bridge that failed
     */
    function recordFailure(
        BridgeType bridgeType
    ) external onlyRole(OPERATOR_ROLE) {
        BridgeConfig storage bridge = bridges[bridgeType];
        bridge.failureCount++;
        bridge.lastFailureTime = block.timestamp;

        // Check health
        _checkBridgeHealth(bridgeType);
    }

    /**
     * @notice Update routing thresholds
     * @param _highValueThreshold High value threshold
     * @param _mediumValueThreshold Medium value threshold
     * @param _multiVerificationThreshold Multi-verification threshold
     */
    function updateThresholds(
        uint256 _highValueThreshold,
        uint256 _mediumValueThreshold,
        uint256 _multiVerificationThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        highValueThreshold = _highValueThreshold;
        mediumValueThreshold = _mediumValueThreshold;
        multiVerificationThreshold = _multiVerificationThreshold;
        emit ThresholdsUpdated(
            _highValueThreshold,
            _mediumValueThreshold,
            _multiVerificationThreshold
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get optimal bridge for a route
     * @param chainId Destination chain
     * @param value Transfer value
     * @return bridgeType Recommended bridge
     */
    function getOptimalBridge(
        uint256 chainId,
        uint256 value
    ) external view returns (BridgeType bridgeType) {
        RoutingDecision memory decision = _determineRouting(chainId, value);
        return decision.primaryBridge;
    }

    /**
     * @notice Get bridge health score
     * @param bridgeType Bridge to check
     * @return score Health score (0-100)
     */
    function getBridgeHealth(
        BridgeType bridgeType
    ) external view returns (uint256 score) {
        BridgeConfig storage bridge = bridges[bridgeType];

        if (bridge.status != BridgeStatus.ACTIVE) {
            return 0;
        }

        uint256 total = bridge.successCount + bridge.failureCount;
        if (total == 0) {
            return bridge.securityScore;
        }

        uint256 successRate = (bridge.successCount * 10000) / total;
        return (bridge.securityScore * successRate) / 10000;
    }

    /**
     * @notice Check if message is verified
     * @param messageHash Message to check
     * @return verified Whether message has sufficient confirmations
     */
    function isMessageVerified(
        bytes32 messageHash
    ) external view returns (bool verified) {
        MessageVerification storage verification = _verifications[messageHash];
        return verification.finalized && verification.approved;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _determineRouting(
        uint256 chainId,
        uint256 value
    ) internal view returns (RoutingDecision memory decision) {
        // High value: use most secure bridge with multi-verification
        if (value >= highValueThreshold) {
            decision.primaryBridge = _getMostSecureBridge(chainId);
            decision.fallbackBridges = _getFallbackBridges(
                chainId,
                decision.primaryBridge
            );
            decision.requireMultiVerification = true;
            decision.minConfirmations = 2;
        }
        // Medium value: use reliable bridge
        else if (value >= mediumValueThreshold) {
            decision.primaryBridge = _getReliableBridge(chainId);
            decision.fallbackBridges = _getFallbackBridges(
                chainId,
                decision.primaryBridge
            );
            decision.requireMultiVerification =
                value >= multiVerificationThreshold;
            decision.minConfirmations = 2;
        }
        // Low value: use fastest bridge
        else {
            decision.primaryBridge = _getFastestBridge(chainId);
            decision.fallbackBridges = _getFallbackBridges(
                chainId,
                decision.primaryBridge
            );
            decision.requireMultiVerification = false;
            decision.minConfirmations = 1;
        }
    }

    function _getMostSecureBridge(
        uint256 chainId
    ) internal view returns (BridgeType) {
        BridgeType best = BridgeType.NATIVE_L2;
        uint256 bestScore = 0;

        for (uint256 i = 0; i <= uint256(type(BridgeType).max); i++) {
            BridgeType bridgeType = BridgeType(i);
            BridgeConfig storage bridge = bridges[bridgeType];

            if (
                bridge.status == BridgeStatus.ACTIVE &&
                supportedChains[bridgeType][chainId] &&
                bridge.securityScore > bestScore
            ) {
                best = bridgeType;
                bestScore = bridge.securityScore;
            }
        }

        if (bestScore == 0) revert NoBridgeAvailable(chainId);
        return best;
    }

    function _getReliableBridge(
        uint256 chainId
    ) internal view returns (BridgeType) {
        // Prefer bridges with high success rate
        BridgeType best = BridgeType.NATIVE_L2;
        uint256 bestReliability = 0;

        for (uint256 i = 0; i <= uint256(type(BridgeType).max); i++) {
            BridgeType bridgeType = BridgeType(i);
            BridgeConfig storage bridge = bridges[bridgeType];

            if (
                bridge.status == BridgeStatus.ACTIVE &&
                supportedChains[bridgeType][chainId]
            ) {
                uint256 total = bridge.successCount + bridge.failureCount;
                uint256 reliability = total > 0
                    ? (bridge.successCount * 100) / total
                    : 50;

                if (reliability > bestReliability) {
                    best = bridgeType;
                    bestReliability = reliability;
                }
            }
        }

        if (bestReliability == 0) revert NoBridgeAvailable(chainId);
        return best;
    }

    function _getFastestBridge(
        uint256 chainId
    ) internal view returns (BridgeType) {
        // For now, prefer LayerZero for speed
        if (
            bridges[BridgeType.LAYERZERO].status == BridgeStatus.ACTIVE &&
            supportedChains[BridgeType.LAYERZERO][chainId]
        ) {
            return BridgeType.LAYERZERO;
        }

        // Fallback to most secure
        return _getMostSecureBridge(chainId);
    }

    function _getFallbackBridges(
        uint256 chainId,
        BridgeType primary
    ) internal view returns (BridgeType[] memory fallbacks) {
        // Count available fallbacks
        uint256 count = 0;
        for (uint256 i = 0; i <= uint256(type(BridgeType).max); i++) {
            BridgeType bridgeType = BridgeType(i);
            if (
                bridgeType != primary &&
                bridges[bridgeType].status == BridgeStatus.ACTIVE &&
                supportedChains[bridgeType][chainId]
            ) {
                count++;
            }
        }

        // Build fallback array
        fallbacks = new BridgeType[](count);
        uint256 index = 0;
        for (uint256 i = 0; i <= uint256(type(BridgeType).max); i++) {
            BridgeType bridgeType = BridgeType(i);
            if (
                bridgeType != primary &&
                bridges[bridgeType].status == BridgeStatus.ACTIVE &&
                supportedChains[bridgeType][chainId]
            ) {
                fallbacks[index++] = bridgeType;
            }
        }
    }

    function _sendViaBridge(
        BridgeType bridgeType,
        uint256 chainId,
        bytes calldata message,
        bytes32 /* messageHash */
    ) internal returns (bool success) {
        BridgeConfig storage bridge = bridges[bridgeType];

        if (bridge.adapter == address(0)) return false;
        if (bridge.status != BridgeStatus.ACTIVE) return false;
        if (!supportedChains[bridgeType][chainId]) return false;

        // Call bridge adapter
        try this._callBridge(bridge.adapter, chainId, message) {
            bridge.successCount++;
            return true;
        } catch (bytes memory returnData) {
            // SECURITY FIX H-9: Prevent OOG padding attacks
            // If the return data is empty, it was likely an Out-Of-Gas error
            // induced maliciously by the caller. Revert instead of degrading.
            if (returnData.length == 0) {
                revert("OOG or low-level error");
            }

            bridge.failureCount++;
            bridge.lastFailureTime = block.timestamp;
            _checkBridgeHealth(bridgeType);
            return false;
        }
    }

    function _callBridge(
        address adapter,
        uint256 /* chainId */,
        bytes calldata message
    ) external {
        require(msg.sender == address(this), "Internal only");
        // Delegate to the registered IBridgeAdapter implementation.
        // The adapter is responsible for encoding the chainId into its own
        // protocol-specific messaging (LayerZero eid, Hyperlane domain, etc.).
        // Refund any excess bridge fees back to this contract.
        IBridgeAdapter(adapter).bridgeMessage(
            adapter, // targetAddress — adapter on destination chain
            message,
            address(this) // refundAddress
        );
    }

    function _tryFallbacks(
        BridgeType[] memory fallbacks,
        uint256 chainId,
        bytes calldata message,
        bytes32 messageHash
    ) internal returns (bool success) {
        for (uint256 i = 0; i < fallbacks.length; i++) {
            if (_sendViaBridge(fallbacks[i], chainId, message, messageHash)) {
                emit BridgeFallback(
                    messageHash,
                    BridgeType.NATIVE_L2,
                    fallbacks[i]
                );
                return true;
            }
        }
        return false;
    }

    function _checkBridgeHealth(BridgeType bridgeType) internal {
        BridgeConfig storage bridge = bridges[bridgeType];

        uint256 total = bridge.successCount + bridge.failureCount;
        if (total < 10) return; // Need minimum sample size

        uint256 failureRate = (bridge.failureCount * 10000) / total;

        if (failureRate >= DEGRADED_THRESHOLD) {
            bridge.status = BridgeStatus.DEGRADED;
            emit HealthCheckFailed(bridgeType, failureRate);
        }
    }

    /**
     * @notice Pause routing
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause routing
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
