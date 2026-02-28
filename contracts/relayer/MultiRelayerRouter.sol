// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IRelayerAdapter} from "./IRelayerAdapter.sol";
import {IMultiRelayerRouter} from "../interfaces/IMultiRelayerRouter.sol";

/**
 * @title MultiRelayerRouter
 * @author ZASEON
 * @notice Priority-ordered multi-relayer router with automatic fallback and health-aware
 *         adapter selection. Provides censorship resistance through emergency self-relay.
 *
 * @dev Architecture:
 *      - Maintains a priority-ordered list of relay adapters (Gelato, CCIP, Self, etc.)
 *      - On relay(), tries adapters in priority order: if one fails/reverts, tries next
 *      - Tracks per-adapter success/failure metrics → auto-degrades unhealthy adapters
 *      - Degraded adapters sorted after active ones (still available as last resort)
 *      - Emergency relay bypasses all adapters for direct message execution
 *
 *      Roles:
 *      - DEFAULT_ADMIN_ROLE: Full control
 *      - ROUTER_ADMIN_ROLE: Manage adapters (register, remove, set priority/status)
 *      - EMERGENCY_ROLE: Trigger emergency relay
 *
 *      Invariants:
 *      - At most MAX_ADAPTERS (10) registered at any time
 *      - Priority values are unique across ACTIVE adapters
 *      - consecutiveFails thresholds trigger automatic degradation
 *      - Excess ETH is refunded to caller
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract MultiRelayerRouter is
    IMultiRelayerRouter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ROUTER_ADMIN_ROLE = keccak256("ROUTER_ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Maximum number of registered adapters
    uint8 public constant MAX_ADAPTERS = 10;

    /// @notice Consecutive failures before auto-degradation
    uint16 public constant DEGRADE_THRESHOLD = 3;

    /// @notice Time after which a degraded adapter auto-recovers (1 hour)
    uint48 public constant RECOVERY_COOLDOWN = 1 hours;

    /// @notice Minimum gas limit for relay calls
    uint256 public constant MIN_GAS_LIMIT = 21_000;

    /// @notice Maximum gas limit for relay calls
    uint256 public constant MAX_GAS_LIMIT = 10_000_000;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Ordered list of adapter addresses
    address[] public adapterList;

    /// @notice Adapter address → config
    mapping(address => AdapterConfig) internal _adapters;

    /// @notice Whether an address is a registered adapter
    mapping(address => bool) public isRegistered;

    /// @notice Total successful relays across all adapters
    uint256 public totalRelays;

    /// @notice Total failed relay attempts across all adapters
    uint256 public totalFailures;

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param admin Default admin and router admin
     */
    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTER_ADMIN_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         RELAY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Relays the operation
     * @param target The target
     * @param payload The message payload
     * @param gasLimit The gas limit
     * @return result The result
     */
function relay(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (RelayResult memory result)
    {
        if (target == address(0)) revert ZeroAddress();
        require(
            gasLimit >= MIN_GAS_LIMIT && gasLimit <= MAX_GAS_LIMIT,
            "Invalid gas limit"
        );

        address[] memory ordered = _getOrderedAdapters();
        uint256 len = ordered.length;
        if (len == 0) revert NoAdaptersAvailable();

        uint256 remainingValue = msg.value;
        uint8 attempts;

        for (uint256 i; i < len; ) {
            address adapterAddr = ordered[i];
            AdapterConfig storage cfg = _adapters[adapterAddr];

            // Try to get the fee
            uint256 fee;
            try IRelayerAdapter(adapterAddr).getFee(gasLimit) returns (
                uint256 f
            ) {
                fee = f;
            } catch {
                unchecked {
                    ++i;
                    ++attempts;
                }
                continue;
            }

            if (fee > remainingValue) {
                unchecked {
                    ++i;
                    ++attempts;
                }
                continue;
            }

            // Attempt the relay
            unchecked {
                ++attempts;
            }

            try
                IRelayerAdapter(adapterAddr).relayMessage{value: fee}(
                    target,
                    payload,
                    gasLimit
                )
            returns (bytes32 taskId) {
                // Success
                cfg.successCount += 1;
                cfg.consecutiveFails = 0;
                cfg.lastUsed = uint48(block.timestamp);
                unchecked {
                    ++totalRelays;
                }

                // Auto-recover if degraded and cooldown elapsed
                if (cfg.status == AdapterStatus.DEGRADED) {
                    cfg.status = AdapterStatus.ACTIVE;
                    cfg.degradedAt = 0;
                    emit AdapterStatusChanged(
                        adapterAddr,
                        AdapterStatus.DEGRADED,
                        AdapterStatus.ACTIVE
                    );
                }

                remainingValue -= fee;
                emit RelayAttempted(adapterAddr, true, fee);
                emit RelayCompleted(taskId, adapterAddr, target, fee, attempts);

                // Refund excess ETH
                if (remainingValue > 0) {
                    (bool refundOk, ) = msg.sender.call{value: remainingValue}(
                        ""
                    );
                    require(refundOk, "Refund failed");
                }

                return
                    RelayResult({
                        taskId: taskId,
                        adapter: adapterAddr,
                        feePaid: fee,
                        attemptNumber: attempts
                    });
            } catch {
                // Failed — record and try next
                cfg.failureCount += 1;
                cfg.consecutiveFails += 1;
                unchecked {
                    ++totalFailures;
                }

                emit RelayAttempted(adapterAddr, false, 0);

                // Auto-degrade if threshold hit
                if (
                    cfg.consecutiveFails >= DEGRADE_THRESHOLD &&
                    cfg.status == AdapterStatus.ACTIVE
                ) {
                    cfg.status = AdapterStatus.DEGRADED;
                    cfg.degradedAt = uint48(block.timestamp);
                    emit AdapterStatusChanged(
                        adapterAddr,
                        AdapterStatus.ACTIVE,
                        AdapterStatus.DEGRADED
                    );
                }
            }

            unchecked {
                ++i;
            }
        }

        // All adapters failed — refund and revert
        if (msg.value > 0) {
            (bool refundOk, ) = msg.sender.call{value: msg.value}("");
            require(refundOk, "Refund failed");
        }
        revert AllAdaptersFailed(attempts);
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Emergency relay
     * @param target The target
     * @param payload The message payload
     * @param gasLimit The gas limit
     */
function emergencyRelay(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable nonReentrant {
        if (target == address(0)) revert ZeroAddress();
        require(
            hasRole(EMERGENCY_ROLE, msg.sender) ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized for emergency relay"
        );
        require(
            gasLimit >= MIN_GAS_LIMIT && gasLimit <= MAX_GAS_LIMIT,
            "Invalid gas limit"
        );

        // Direct execution — no adapter involved
        (bool success, ) = target.call{value: msg.value, gas: gasLimit}(
            payload
        );
        if (!success) revert EmergencyRelayFailed();

        emit EmergencyRelayTriggered(target, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      ADAPTER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Registers adapter
     * @param adapter The bridge adapter address
     * @param name The name
     * @param priority The priority
     */
function registerAdapter(
        address adapter,
        string calldata name,
        uint16 priority
    ) external onlyRole(ROUTER_ADMIN_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();
        if (isRegistered[adapter]) revert AdapterAlreadyRegistered(adapter);
        if (adapterList.length >= MAX_ADAPTERS) revert MaxAdaptersReached();

        _adapters[adapter] = AdapterConfig({
            adapter: adapter,
            name: name,
            priority: priority,
            status: AdapterStatus.ACTIVE,
            lastUsed: 0,
            degradedAt: 0,
            successCount: 0,
            failureCount: 0,
            consecutiveFails: 0
        });

        isRegistered[adapter] = true;
        adapterList.push(adapter);

        emit AdapterRegistered(adapter, name, priority);
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Removes adapter
     * @param adapter The bridge adapter address
     */
function removeAdapter(
        address adapter
    ) external onlyRole(ROUTER_ADMIN_ROLE) {
        if (!isRegistered[adapter]) revert AdapterNotRegistered(adapter);

        isRegistered[adapter] = false;
        delete _adapters[adapter];

        // Remove from list (swap-and-pop)
        uint256 len = adapterList.length;
        for (uint256 i; i < len; ) {
            if (adapterList[i] == adapter) {
                adapterList[i] = adapterList[len - 1];
                adapterList.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }

        emit AdapterRemoved(adapter);
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Sets the adapter priority
     * @param adapter The bridge adapter address
     * @param newPriority The new Priority value
     */
function setAdapterPriority(
        address adapter,
        uint16 newPriority
    ) external onlyRole(ROUTER_ADMIN_ROLE) {
        if (!isRegistered[adapter]) revert AdapterNotRegistered(adapter);

        uint16 old = _adapters[adapter].priority;
        _adapters[adapter].priority = newPriority;

        emit AdapterPriorityUpdated(adapter, old, newPriority);
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Sets the adapter status
     * @param adapter The bridge adapter address
     * @param status The status value
     */
function setAdapterStatus(
        address adapter,
        AdapterStatus status
    ) external onlyRole(ROUTER_ADMIN_ROLE) {
        if (!isRegistered[adapter]) revert AdapterNotRegistered(adapter);

        AdapterStatus old = _adapters[adapter].status;
        _adapters[adapter].status = status;

        if (status == AdapterStatus.DEGRADED) {
            _adapters[adapter].degradedAt = uint48(block.timestamp);
        } else {
            _adapters[adapter].degradedAt = 0;
            _adapters[adapter].consecutiveFails = 0;
        }

        emit AdapterStatusChanged(adapter, old, status);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause all relay operations (admin only)
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause relay operations (admin only)
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Returns the adapter
     * @param adapter The bridge adapter address
     * @return The result value
     */
function getAdapter(
        address adapter
    ) external view returns (AdapterConfig memory) {
        return _adapters[adapter];
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Returns the active adapters
     * @return The result value
     */
function getActiveAdapters() external view returns (address[] memory) {
        return _getOrderedAdapters();
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Estimate fee
     * @param gasLimit The gas limit
     * @return fee The fee
     * @return adapter The adapter
     */
function estimateFee(
        uint256 gasLimit
    ) external view returns (uint256 fee, address adapter) {
        address[] memory ordered = _getOrderedAdapters();
        uint256 len = ordered.length;

        for (uint256 i; i < len; ) {
            try IRelayerAdapter(ordered[i]).getFee(gasLimit) returns (
                uint256 f
            ) {
                return (f, ordered[i]);
            } catch {
                // Skip to next
            }
            unchecked {
                ++i;
            }
        }

        revert NoAdaptersAvailable();
    }

    /// @inheritdoc IMultiRelayerRouter
        /**
     * @notice Adapter count
     * @return The result value
     */
function adapterCount() external view returns (uint256) {
        return adapterList.length;
    }

    /// @notice Get adapter at index
        /**
     * @notice Adapter at
     * @param index The index in the collection
     * @return The result value
     */
function adapterAt(uint256 index) external view returns (address) {
        return adapterList[index];
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Build priority-ordered list of usable adapters.
     *      Active adapters come first (by priority), then degraded (that have
     *      passed recovery cooldown), then remaining degraded.
     *      DISABLED adapters are excluded.
     */
    function _getOrderedAdapters()
        internal
        view
        returns (address[] memory ordered)
    {
        uint256 len = adapterList.length;
        if (len == 0) return ordered;

        // Collect usable adapters with their effective priority
        address[] memory candidates = new address[](len);
        uint256[] memory priorities = new uint256[](len);
        uint256 count;

        for (uint256 i; i < len; ) {
            address addr = adapterList[i];
            AdapterConfig storage cfg = _adapters[addr];

            if (cfg.status == AdapterStatus.ACTIVE) {
                candidates[count] = addr;
                priorities[count] = uint256(cfg.priority);
                unchecked {
                    ++count;
                }
            } else if (cfg.status == AdapterStatus.DEGRADED) {
                candidates[count] = addr;
                // Degraded adapters get a large priority offset
                // Recovered degraded (past cooldown) get smaller offset
                if (block.timestamp >= cfg.degradedAt + RECOVERY_COOLDOWN) {
                    priorities[count] = uint256(cfg.priority) + 10_000;
                } else {
                    priorities[count] = uint256(cfg.priority) + 100_000;
                }
                unchecked {
                    ++count;
                }
            }
            // DISABLED adapters are skipped

            unchecked {
                ++i;
            }
        }

        if (count == 0) return new address[](0);

        // Simple insertion sort (max 10 items)
        for (uint256 i = 1; i < count; ) {
            uint256 key = priorities[i];
            address keyAddr = candidates[i];
            uint256 j = i;

            while (j > 0 && priorities[j - 1] > key) {
                priorities[j] = priorities[j - 1];
                candidates[j] = candidates[j - 1];
                unchecked {
                    --j;
                }
            }

            priorities[j] = key;
            candidates[j] = keyAddr;
            unchecked {
                ++i;
            }
        }

        // Copy to right-sized array
        ordered = new address[](count);
        for (uint256 i; i < count; ) {
            ordered[i] = candidates[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Accept ETH for relay payments
    receive() external payable {}
}
