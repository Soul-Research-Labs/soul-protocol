// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProtocolEmergencyCoordinator} from "../interfaces/IProtocolEmergencyCoordinator.sol";

/**
 * @title CrossChainEmergencyRelay
 * @author ZASEON
 * @notice Propagates emergency state across L2 deployments by encoding
 *         severity-level messages and fanning them out to all registered
 *         chains via a generic messenger interface.
 *
 * @dev Design principles:
 *  - Bridge-agnostic: works with any messenger that implements sendMessage()
 *  - Heartbeat liveness: L2 receivers can auto-pause if no heartbeat arrives
 *    within a configurable window (off-chain monitoring feeds the heartbeat)
 *  - Replay protection: emergency nonces per chain + chain ID validation
 *  - Fail-open on send: if one chain's relay fails, others still get the message
 *
 * Integration:
 *  - ProtocolEmergencyCoordinator calls broadcastEmergency() after
 *    executeEmergencyPlan() to propagate to L2 deployments
 *  - On L2: a mirror contract (or lightweight receiver) decodes the message
 *    and triggers local pause/unpause
 */
contract CrossChainEmergencyRelay is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant BROADCASTER_ROLE = keccak256("BROADCASTER_ROLE");
    bytes32 public constant RECEIVER_ROLE = keccak256("RECEIVER_ROLE");
    bytes32 public constant HEARTBEAT_ROLE = keccak256("HEARTBEAT_ROLE");

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_CHAINS = 20;
    uint48 public constant DEFAULT_HEARTBEAT_INTERVAL = 1 hours;
    uint48 public constant MIN_HEARTBEAT_INTERVAL = 10 minutes;
    uint48 public constant MAX_HEARTBEAT_INTERVAL = 24 hours;

    /// @dev Magic prefix for emergency messages to prevent accidental relay
    bytes4 public constant EMERGENCY_PREFIX = 0x454D5247; // "EMRG"

    /*//////////////////////////////////////////////////////////////
                             STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ChainConfig {
        uint256 chainId;
        address messenger; // L1 messenger/bridge that can send to this chain
        address remoteReceiver; // Address of the receiver contract on that L2
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

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                           IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    uint256 public immutable deployChainId;

    /*//////////////////////////////////////////////////////////////
                             STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Global emergency nonce (increments per broadcast)
    uint256 public globalNonce;

    /// @notice Last received nonce per source chain (replay protection)
    mapping(uint256 => uint256) public lastReceivedNonce;

    /// @notice Registered chain configurations
    mapping(uint256 => ChainConfig) public chains;

    /// @notice Array of registered chain IDs for iteration
    uint256[] public registeredChainIds;

    /// @notice Current received severity (on L2 side)
    IProtocolEmergencyCoordinator.Severity public receivedSeverity;

    /// @notice Heartbeat state
    HeartbeatState public heartbeat;

    /// @notice Maximum age for accepting emergency messages (prevents stale replays)
    uint48 public maxMessageAge = 1 hours;

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the emergency relay with admin roles and default heartbeat
    /// @param _admin Address to receive all administrative and operational roles
    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        deployChainId = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(BROADCASTER_ROLE, _admin);
        _grantRole(RECEIVER_ROLE, _admin);
        _grantRole(HEARTBEAT_ROLE, _admin);

        heartbeat.interval = DEFAULT_HEARTBEAT_INTERVAL;
        heartbeat.lastHeartbeatAt = uint48(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                      CHAIN REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an L2 chain for emergency message propagation
     * @param chainId The destination chain ID
     * @param messenger The L1 messenger/bridge contract for this chain
     * @param remoteReceiver The receiver contract address on the L2
     */
    function registerChain(
        uint256 chainId,
        address messenger,
        address remoteReceiver
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (chainId == 0 || chainId == deployChainId) revert InvalidChainId();
        if (messenger == address(0) || remoteReceiver == address(0))
            revert ZeroAddress();
        if (chains[chainId].active) revert ChainAlreadyRegistered(chainId);
        if (registeredChainIds.length >= MAX_CHAINS) revert MaxChainsReached();

        chains[chainId] = ChainConfig({
            chainId: chainId,
            messenger: messenger,
            remoteReceiver: remoteReceiver,
            active: true,
            lastBroadcastAt: 0
        });

        registeredChainIds.push(chainId);

        emit ChainRegistered(chainId, messenger, remoteReceiver);
    }

    /**
     * @notice Deactivate a chain (stops receiving emergency broadcasts)
          * @param chainId The chain identifier
     */
    function deactivateChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!chains[chainId].active) revert ChainNotRegistered(chainId);
        chains[chainId].active = false;
        emit ChainDeactivated(chainId);
    }

    /**
     * @notice Reactivate a previously deactivated chain
          * @param chainId The chain identifier
     */
    function reactivateChain(
        uint256 chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ChainConfig storage cfg = chains[chainId];
        if (cfg.chainId == 0) revert ChainNotRegistered(chainId);
        cfg.active = true;
        emit ChainReactivated(chainId);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY BROADCASTING (L1)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Broadcast an emergency to all registered L2 chains.
     *         Encodes the severity + incident data and attempts to send
     *         via each chain's registered messenger.
     * @param severity The severity level to propagate
     * @param incidentId The incident ID from the coordinator
     */
    function broadcastEmergency(
        IProtocolEmergencyCoordinator.Severity severity,
        uint256 incidentId
    ) external onlyRole(BROADCASTER_ROLE) nonReentrant whenNotPaused {
        uint256 nonce;
        unchecked {
            nonce = ++globalNonce;
        }

        uint256 notified;
        uint256 failed;
        uint256 length = registeredChainIds.length;

        for (uint256 i; i < length; ) {
            uint256 cid = registeredChainIds[i];
            ChainConfig storage cfg = chains[cid];

            if (cfg.active) {
                EmergencyMessage memory msg_ = EmergencyMessage({
                    prefix: EMERGENCY_PREFIX,
                    nonce: nonce,
                    sourceChainId: deployChainId,
                    targetChainId: cid,
                    severity: severity,
                    incidentId: incidentId,
                    timestamp: uint48(block.timestamp)
                });

                bytes memory encoded = abi.encode(msg_);

                // Try to send — fail-open so other chains still get notified
                // Messenger expected to have: sendMessage(address to, bytes data)
                (bool ok, ) = cfg.messenger.call(
                    abi.encodeWithSignature(
                        "sendMessage(address,bytes)",
                        cfg.remoteReceiver,
                        encoded
                    )
                );

                if (ok) {
                    cfg.lastBroadcastAt = uint48(block.timestamp);
                    unchecked {
                        ++notified;
                    }
                } else {
                    unchecked {
                        ++failed;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        emit EmergencyBroadcasted(incidentId, severity, notified, failed);
    }

    /**
     * @notice Broadcast recovery (GREEN) to all L2 chains
     * @param incidentId The resolved incident ID
     */
    function broadcastRecovery(
        uint256 incidentId
    ) external onlyRole(BROADCASTER_ROLE) nonReentrant whenNotPaused {
        uint256 nonce;
        unchecked {
            nonce = ++globalNonce;
        }

        uint256 notified;
        uint256 length = registeredChainIds.length;

        for (uint256 i; i < length; ) {
            uint256 cid = registeredChainIds[i];
            ChainConfig storage cfg = chains[cid];

            if (cfg.active) {
                EmergencyMessage memory msg_ = EmergencyMessage({
                    prefix: EMERGENCY_PREFIX,
                    nonce: nonce,
                    sourceChainId: deployChainId,
                    targetChainId: cid,
                    severity: IProtocolEmergencyCoordinator.Severity.GREEN,
                    incidentId: incidentId,
                    timestamp: uint48(block.timestamp)
                });

                bytes memory encoded = abi.encode(msg_);

                (bool ok, ) = cfg.messenger.call(
                    abi.encodeWithSignature(
                        "sendMessage(address,bytes)",
                        cfg.remoteReceiver,
                        encoded
                    )
                );

                if (ok) {
                    cfg.lastBroadcastAt = uint48(block.timestamp);
                    unchecked {
                        ++notified;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        emit RecoveryBroadcasted(incidentId, notified);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY RECEIVING (L2)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and process an emergency message from L1.
     *         Called by the L2 bridge/messenger when a message arrives.
     * @param encodedMessage The ABI-encoded EmergencyMessage
     */
    function receiveEmergency(
        bytes calldata encodedMessage
    ) external onlyRole(RECEIVER_ROLE) nonReentrant {
        EmergencyMessage memory msg_ = abi.decode(
            encodedMessage,
            (EmergencyMessage)
        );

        // Validate prefix
        if (msg_.prefix != EMERGENCY_PREFIX) revert InvalidMessage();

        // Validate target chain
        if (msg_.targetChainId != deployChainId) revert InvalidChainId();

        // Replay protection: nonce must be strictly increasing per source
        if (msg_.nonce <= lastReceivedNonce[msg_.sourceChainId]) {
            revert ReplayDetected(msg_.sourceChainId, msg_.nonce);
        }

        // Message freshness check
        if (block.timestamp > msg_.timestamp + maxMessageAge) {
            revert MessageTooOld(msg_.timestamp, maxMessageAge);
        }

        lastReceivedNonce[msg_.sourceChainId] = msg_.nonce;
        receivedSeverity = msg_.severity;

        emit EmergencyReceived(
            msg_.incidentId,
            msg_.sourceChainId,
            msg_.severity
        );

        // Auto-execute local actions based on severity
        if (msg_.severity >= IProtocolEmergencyCoordinator.Severity.RED) {
            // Self-pause this relay (prevents further non-emergency operations)
            if (!paused()) {
                _pause();
                emit AutoPauseTriggered("Emergency severity RED received");
            }
        } else if (
            msg_.severity == IProtocolEmergencyCoordinator.Severity.GREEN
        ) {
            // Recovery: unpause if we were auto-paused
            if (paused() && heartbeat.autoPauseTriggered) {
                _unpause();
                heartbeat.autoPauseTriggered = false;
                emit AutoPauseRecovered();
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                      HEARTBEAT MECHANISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a heartbeat to a specific chain (called by off-chain monitor)
     * @param chainId The chain to send the heartbeat to
     */
    function sendHeartbeat(
        uint256 chainId
    ) external onlyRole(HEARTBEAT_ROLE) whenNotPaused {
        ChainConfig storage cfg = chains[chainId];
        if (!cfg.active) revert ChainNotRegistered(chainId);

        bytes memory payload = abi.encode(
            bytes4(0x48454152), // "HEAR" (heartbeat prefix)
            deployChainId,
            uint48(block.timestamp)
        );

        (bool ok, ) = cfg.messenger.call(
            abi.encodeWithSignature(
                "sendMessage(address,bytes)",
                cfg.remoteReceiver,
                payload
            )
        );

        if (!ok) revert SendFailed(chainId);

        emit HeartbeatSent(chainId, uint48(block.timestamp));
    }

    /**
     * @notice Receive a heartbeat on L2 (resets the heartbeat timer)
     * @param sourceChainId The chain that sent the heartbeat
     */
    function receiveHeartbeat(
        uint256 sourceChainId
    ) external onlyRole(RECEIVER_ROLE) {
        heartbeat.lastHeartbeatAt = uint48(block.timestamp);

        // If we were auto-paused due to heartbeat timeout, recover
        if (heartbeat.autoPauseTriggered && !_isEmergency()) {
            heartbeat.autoPauseTriggered = false;
            if (paused()) {
                _unpause();
                emit AutoPauseRecovered();
            }
        }

        emit HeartbeatReceived(sourceChainId, uint48(block.timestamp));
    }

    /**
     * @notice Check and trigger auto-pause if heartbeat is overdue.
     *         Can be called by anyone (permissionless liveness check).
     */
    function checkHeartbeatLiveness() external {
        if (heartbeat.autoPauseTriggered) return; // Already triggered

        uint48 deadline = heartbeat.lastHeartbeatAt + heartbeat.interval;
        if (block.timestamp > deadline) {
            heartbeat.autoPauseTriggered = true;
            if (!paused()) {
                _pause();
                emit AutoPauseTriggered("Heartbeat timeout");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the heartbeat interval
     * @param newInterval New interval in seconds
     */
    function setHeartbeatInterval(
        uint48 newInterval
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            newInterval < MIN_HEARTBEAT_INTERVAL ||
            newInterval > MAX_HEARTBEAT_INTERVAL
        ) {
            revert InvalidHeartbeatInterval();
        }

        uint48 old = heartbeat.interval;
        heartbeat.interval = newInterval;
        emit HeartbeatIntervalUpdated(old, newInterval);
    }

    /**
     * @notice Update the maximum message age for freshness checks
     * @param newMaxAge New max age in seconds (must be > 0 and <= 24 hours)
     */
    function setMaxMessageAge(
        uint48 newMaxAge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newMaxAge == 0 || newMaxAge > 24 hours) revert InvalidMessage();
        maxMessageAge = newMaxAge;
    }

    /// @notice Admin pause
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Admin unpause
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
        heartbeat.autoPauseTriggered = false;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get all registered chain IDs
        /**
     * @notice Returns the registered chain ids
     * @return The result value
     */
function getRegisteredChainIds() external view returns (uint256[] memory) {
        return registeredChainIds;
    }

    /// @notice Get the number of active chains
        /**
     * @notice Active chain count
     * @return count The count
     */
function activeChainCount() external view returns (uint256 count) {
        uint256 length = registeredChainIds.length;
        for (uint256 i; i < length; ) {
            if (chains[registeredChainIds[i]].active) {
                unchecked {
                    ++count;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Whether the heartbeat is overdue
        /**
     * @notice Checks if heartbeat overdue
     * @return The result value
     */
function isHeartbeatOverdue() external view returns (bool) {
        return block.timestamp > heartbeat.lastHeartbeatAt + heartbeat.interval;
    }

    /// @notice Whether we are in an emergency state (received severity >= YELLOW)
        /**
     * @notice Checks if in emergency
     * @return The result value
     */
function isInEmergency() external view returns (bool) {
        return _isEmergency();
    }

    /*//////////////////////////////////////////////////////////////
                      INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _isEmergency() internal view returns (bool) {
        return receivedSeverity > IProtocolEmergencyCoordinator.Severity.GREEN;
    }
}
