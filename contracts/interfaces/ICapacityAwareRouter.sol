// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDynamicRoutingOrchestrator} from "./IDynamicRoutingOrchestrator.sol";

/**
 * @title ICapacityAwareRouter
 * @notice Interface for the CapacityAwareRouter cross-chain relay contract
 * @dev Capacity-aware router that executes routes from DynamicRoutingOrchestrator
 */
interface ICapacityAwareRouter {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum RelayStatus {
        NONE,
        COMMITTED,
        EXECUTING,
        COMPLETED,
        FAILED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RelayOperation {
        bytes32 routeId;
        address user;
        uint256 sourceChainId;
        uint256 destChainId;
        uint256 amount;
        uint256 fee;
        uint256 protocolFee;
        RelayStatus status;
        uint48 committedAt;
        uint48 completedAt;
        address destRecipient;
    }

    struct PairMetrics {
        uint256 totalVolume;
        uint256 totalCosts;
        uint256 relayCount;
        uint48 lastRelay;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RelayCommitted(
        bytes32 indexed relayId,
        bytes32 indexed routeId,
        address indexed user,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        uint256 fee
    );

    event RelayExecuting(bytes32 indexed relayId, address indexed executor);

    event RelayCompleted(
        bytes32 indexed relayId,
        uint48 completionTime,
        uint256 actualFee
    );

    event RelayFailed(bytes32 indexed relayId, string reason);

    event RelayRefunded(
        bytes32 indexed relayId,
        address indexed user,
        uint256 amount
    );

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    event CooldownUpdated(uint48 oldCooldown, uint48 newCooldown);

    event TimeoutUpdated(uint48 oldTimeout, uint48 newTimeout);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error RelayAmountTooLarge(uint256 amount, uint256 max);
    error CooldownNotElapsed(address user, uint48 remaining);
    error RelayNotFound(bytes32 relayId);
    error InvalidRelayStatus(
        bytes32 relayId,
        RelayStatus current,
        RelayStatus expected
    );
    error RelayTimedOut(bytes32 relayId);
    error RelayNotTimedOut(bytes32 relayId);
    error InsufficientPayment(uint256 required, uint256 provided);
    error NoFeesToWithdraw();
    error WithdrawFailed();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function EXECUTOR_ROLE() external view returns (bytes32);

    function COMPLETER_ROLE() external view returns (bytes32);

    function RELAY_FEE_BPS() external view returns (uint16);

    function BPS() external view returns (uint16);

    function DEFAULT_COOLDOWN() external view returns (uint48);

    function MAX_RELAY_AMOUNT() external view returns (uint256);

    function orchestrator() external view returns (IDynamicRoutingOrchestrator);

    function accumulatedFees() external view returns (uint256);

    function relayTimeout() external view returns (uint48);

    function userCooldown() external view returns (uint48);

    function lastRelayAt(address user) external view returns (uint48);

    /*//////////////////////////////////////////////////////////////
                        RELAY LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function quoteRelay(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        IDynamicRoutingOrchestrator.Urgency urgency
    )
        external
        view
        returns (
            IDynamicRoutingOrchestrator.Route memory route,
            uint256 totalRequired
        );

    function commitRelay(
        bytes32 routeId,
        address destRecipient
    ) external payable returns (bytes32 relayId);

    function beginExecution(bytes32 relayId) external;

    function completeRelay(bytes32 relayId, uint48 actualLatency) external;

    function failRelay(bytes32 relayId, string calldata reason) external;

    function refundTimedOut(bytes32 relayId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getRelayOp(
        bytes32 relayId
    ) external view returns (RelayOperation memory t);

    function getPairMetrics(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (PairMetrics memory metrics);

    function canUserRelay(
        address user
    ) external view returns (bool canRelay, uint48 cooldownRemaining);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function withdrawFees(address recipient) external;

    function setCooldown(uint48 newCooldown) external;

    function setTimeout(uint48 newTimeout) external;

    function pause() external;

    function unpause() external;
}
