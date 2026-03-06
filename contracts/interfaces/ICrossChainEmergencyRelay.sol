// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProtocolEmergencyCoordinator} from "./IProtocolEmergencyCoordinator.sol";

/**
 * @title ICrossChainEmergencyRelay
 * @notice Interface for cross-chain emergency state propagation across L2 deployments
 */
interface ICrossChainEmergencyRelay {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct ChainConfig {
        uint256 chainId;
        address messenger;
        address remoteReceiver;
        bool active;
        uint48 lastBroadcastAt;
    }

    struct EmergencyMessage {
        bytes4 prefix;
        uint256 nonce;
        uint256 sourceChainId;
        uint256 targetChainId;
        IProtocolEmergencyCoordinator.Severity severity;
        uint256 incidentId;
        uint48 timestamp;
    }

    struct HeartbeatState {
        uint48 lastHeartbeatAt;
        uint48 interval;
        bool autoPauseTriggered;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ChainRegistered(
        uint256 indexed chainId,
        address messenger,
        address remoteReceiver
    );
    event ChainDeactivated(uint256 indexed chainId);
    event ChainReactivated(uint256 indexed chainId);
    event EmergencyBroadcasted(
        uint256 indexed incidentId,
        IProtocolEmergencyCoordinator.Severity severity,
        uint256 chainsNotified,
        uint256 chainsFailed
    );
    event EmergencyReceived(
        uint256 indexed incidentId,
        uint256 indexed sourceChainId,
        IProtocolEmergencyCoordinator.Severity severity
    );
    event RecoveryBroadcasted(
        uint256 indexed incidentId,
        uint256 chainsNotified
    );
    event HeartbeatSent(uint256 indexed chainId, uint48 timestamp);
    event HeartbeatReceived(uint256 indexed sourceChainId, uint48 timestamp);
    event HeartbeatIntervalUpdated(uint48 oldInterval, uint48 newInterval);
    event AutoPauseTriggered(string reason);
    event AutoPauseRecovered();

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error ChainAlreadyRegistered(uint256 chainId);
    error ChainNotRegistered(uint256 chainId);
    error MaxChainsReached();
    error InvalidChainId();
    error InvalidHeartbeatInterval();
    error InvalidMessage();
    error ReplayDetected(uint256 chainId, uint256 nonce);
    error MessageTooOld(uint48 timestamp, uint48 maxAge);
    error SendFailed(uint256 chainId);

    // =========================================================================
    // CHAIN REGISTRATION
    // =========================================================================

    function registerChain(
        uint256 chainId,
        address messenger,
        address remoteReceiver
    ) external;

    function deactivateChain(uint256 chainId) external;

    function reactivateChain(uint256 chainId) external;

    // =========================================================================
    // EMERGENCY BROADCASTING
    // =========================================================================

    function broadcastEmergency(
        IProtocolEmergencyCoordinator.Severity severity,
        uint256 incidentId
    ) external;

    function broadcastRecovery(uint256 incidentId) external;

    // =========================================================================
    // EMERGENCY RECEIVING
    // =========================================================================

    function receiveEmergency(bytes calldata encodedMessage) external;

    // =========================================================================
    // HEARTBEAT
    // =========================================================================

    function sendHeartbeat(uint256 chainId) external;

    function receiveHeartbeat(uint256 sourceChainId) external;

    function checkHeartbeatLiveness() external;

    // =========================================================================
    // ADMIN
    // =========================================================================

    function setHeartbeatInterval(uint48 newInterval) external;

    function setMaxMessageAge(uint48 newMaxAge) external;

    function pause() external;

    function unpause() external;

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function deployChainId() external view returns (uint256);

    function globalNonce() external view returns (uint256);

    function lastReceivedNonce(uint256 chainId) external view returns (uint256);

    function chains(
        uint256 chainId
    )
        external
        view
        returns (
            uint256 chainId_,
            address messenger,
            address remoteReceiver,
            bool active,
            uint48 lastBroadcastAt
        );

    function registeredChainIds(uint256 index) external view returns (uint256);

    function receivedSeverity()
        external
        view
        returns (IProtocolEmergencyCoordinator.Severity);

    function heartbeat()
        external
        view
        returns (
            uint48 lastHeartbeatAt,
            uint48 interval,
            bool autoPauseTriggered
        );

    function maxMessageAge() external view returns (uint48);

    function getRegisteredChainIds() external view returns (uint256[] memory);

    function activeChainCount() external view returns (uint256 count);

    function isHeartbeatOverdue() external view returns (bool);

    function isInEmergency() external view returns (bool);
}
