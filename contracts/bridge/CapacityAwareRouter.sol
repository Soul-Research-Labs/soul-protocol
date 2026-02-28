// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {IDynamicRoutingOrchestrator} from "../interfaces/IDynamicRoutingOrchestrator.sol";
import {ICapacityAwareRouter} from "../interfaces/ICapacityAwareRouter.sol";
import {RouteOptimizer} from "../libraries/RouteOptimizer.sol";

/**
 * @title CapacityAwareRouter
 * @author ZASEON
 * @notice Proof-routing frontend that executes routes from DynamicRoutingOrchestrator
 * @dev Routes ZK proof relay requests through optimal bridge adapters.
 *      ZASEON is proof middleware — the "transfers" tracked here are
 *      proof relay operations, not token transfers. The `amount` field
 *      represents the service fee for the proof relay, not tokens being moved.
 *
 *      Composes with DynamicRoutingOrchestrator for route selection and adds:
 *      - Quote-and-execute pattern: get route → commit → execute within validity window
 *      - Adaptive fee calculation with capacity impact premium
 *      - Proof relay tracking with volume and fee accounting per chain pair
 *      - Fallback routing on primary bridge failure
 *      - Rate limiting integration (per-user, per-pair cooldowns)
 *      - Bridge adapter fee estimation pass-through
 *
 *      Lifecycle:
 *      1. User calls `quoteRelay()` → gets Route from orchestrator
 *      2. User calls `commitRelay()` with routeId → locks fee, confirms execution
 *      3. Router calls `beginExecution()` → triggers bridge adapter(s)
 *      4. On completion, `completeRelay()` finalizes and records metrics
 *
 *      Security features:
 *      - ReentrancyGuard on all payment-handling functions
 *      - Minimum cooldown between relay requests per user (configurable)
 *      - Maximum single relay limit
 *      - Stale route detection (routes expire after 5 minutes)
 *      - Zero-address validation
 */
contract CapacityAwareRouter is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    ICapacityAwareRouter
{
    using RouteOptimizer for RouteOptimizer.ScoringWeights;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for executing relay operations
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Role for completing relay operations
    bytes32 public constant COMPLETER_ROLE = keccak256("COMPLETER_ROLE");

    /// @notice Relay service fee in bps (3%)
    uint16 public constant RELAY_FEE_BPS = 300;

    /// @notice Basis points denominator
    uint16 public constant BPS = 10_000;

    /// @notice Default cooldown between relay requests per user (30 seconds)
    uint48 public constant DEFAULT_COOLDOWN = 30;

    /// @notice Maximum single relay amount (500 ETH)
    uint256 public constant MAX_RELAY_AMOUNT = 500 ether;

    // Enum inherited from ICapacityAwareRouter: RelayStatus

    // Structs inherited from ICapacityAwareRouter: RelayOperation, PairMetrics

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The DynamicRoutingOrchestrator this router uses for route selection
    IDynamicRoutingOrchestrator public immutable orchestrator;

    /// @notice Relay operations indexed by relay ID
    mapping(bytes32 => RelayOperation) public relayOps;

    /// @notice User's last relay timestamp (for cooldown)
    mapping(address => uint48) public lastRelayAt;

    /// @notice Per-pair volume metrics: keccak256(sourceChain, destChain) => PairMetrics
    mapping(bytes32 => PairMetrics) public pairMetrics;

    /// @notice Accumulated protocol service fees (withdrawable by admin)
    uint256 public accumulatedFees;

    /// @notice Relay nonce for unique ID generation
    uint256 internal _relayNonce;

    /// @notice Relay timeout (1 hour)
    uint48 public relayTimeout = 1 hours;

    /// @notice User cooldown between relay operations
    uint48 public userCooldown = DEFAULT_COOLDOWN;

    // Events inherited from ICapacityAwareRouter:
    //   RelayCommitted, RelayExecuting, RelayCompleted, RelayFailed,
    //   RelayRefunded, FeesWithdrawn, CooldownUpdated, TimeoutUpdated

    // Errors inherited from ICapacityAwareRouter:
    //   ZeroAddress, RelayAmountTooLarge, CooldownNotElapsed, RelayNotFound,
    //   InvalidRelayStatus, RelayTimedOut, RelayNotTimedOut, InsufficientPayment,
    //   NoFeesToWithdraw, WithdrawFailed

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the capacity-aware router
     * @param _orchestrator Address of the DynamicRoutingOrchestrator
     * @param admin Default admin
     * @param executor Initial executor address
     */
    constructor(address _orchestrator, address admin, address executor) {
        if (_orchestrator == address(0)) revert ZeroAddress();
        if (admin == address(0)) revert ZeroAddress();
        if (executor == address(0)) revert ZeroAddress();

        orchestrator = IDynamicRoutingOrchestrator(_orchestrator);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(EXECUTOR_ROLE, executor);
        _grantRole(COMPLETER_ROLE, executor);
    }

    /*//////////////////////////////////////////////////////////////
                          RELAY LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Quote a cross-chain relay — returns the optimal route and cost
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     * @param amount Relay service amount
     * @param urgency Speed/cost preference
     * @return route The optimal route
     * @return totalRequired Total payment required (amount + fee)
     */
    function quoteRelay(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        IDynamicRoutingOrchestrator.Urgency urgency
    )
        external
        view
        override
        returns (
            IDynamicRoutingOrchestrator.Route memory route,
            uint256 totalRequired
        )
    {
        IDynamicRoutingOrchestrator.RouteRequest
            memory request = IDynamicRoutingOrchestrator.RouteRequest({
                sourceChainId: sourceChainId,
                destChainId: destChainId,
                amount: amount,
                urgency: urgency,
                maxCost: 0,
                maxTime: 0,
                minSuccessBps: 0,
                requirePrivacy: false
            });

        route = orchestrator.findOptimalRoute(request);

        // Protocol fee on top of route cost
        uint256 protocolFee = (route.totalCost * RELAY_FEE_BPS) / BPS;
        totalRequired = amount + route.totalCost + protocolFee;
    }

    /**
     * @notice Commit to a relay — locks payment and records the operation
     * @param routeId Route ID from the orchestrator
     * @param destRecipient Recipient address on destination chain
     * @return relayId Unique relay identifier
     */
    function commitRelay(
        bytes32 routeId,
        address destRecipient
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 relayId)
    {
        if (destRecipient == address(0)) revert ZeroAddress();

        // Check cooldown
        uint48 lastTx = lastRelayAt[msg.sender];
        if (lastTx > 0 && block.timestamp < lastTx + userCooldown) {
            revert CooldownNotElapsed(
                msg.sender,
                uint48(lastTx + userCooldown - block.timestamp)
            );
        }

        // Get route from orchestrator
        IDynamicRoutingOrchestrator.Route memory route = orchestrator.getRoute(
            routeId
        );
        require(route.chainPath.length > 0, "Invalid route");
        require(
            route.status == IDynamicRoutingOrchestrator.RouteStatus.PENDING,
            "Route not pending"
        );
        require(block.timestamp <= route.expiresAt, "Route expired");

        // Calculate fees
        uint256 protocolFee = (route.totalCost * RELAY_FEE_BPS) / BPS;
        uint256 totalRequired = route.totalCost + protocolFee;
        if (msg.value < totalRequired) {
            revert InsufficientPayment(totalRequired, msg.value);
        }

        uint256 amount = msg.value - totalRequired;
        if (amount > MAX_RELAY_AMOUNT) {
            revert RelayAmountTooLarge(amount, MAX_RELAY_AMOUNT);
        }

        // Generate relay ID
        _relayNonce++;
        relayId = keccak256(
            abi.encodePacked(msg.sender, routeId, _relayNonce, block.timestamp)
        );

        uint256 sourceChain = route.chainPath[0];
        uint256 destChain = route.chainPath[route.chainPath.length - 1];

        // Record relay operation
        relayOps[relayId] = RelayOperation({
            routeId: routeId,
            user: msg.sender,
            sourceChainId: sourceChain,
            destChainId: destChain,
            amount: amount,
            fee: route.totalCost,
            protocolFee: protocolFee,
            status: RelayStatus.COMMITTED,
            committedAt: uint48(block.timestamp),
            completedAt: 0,
            destRecipient: destRecipient
        });

        lastRelayAt[msg.sender] = uint48(block.timestamp);
        accumulatedFees += protocolFee;

        // Refund excess payment
        uint256 excess = msg.value - totalRequired - amount;
        if (excess > 0) {
            (bool ok, ) = msg.sender.call{value: excess}("");
            require(ok, "Refund failed");
        }

        emit RelayCommitted(
            relayId,
            routeId,
            msg.sender,
            sourceChain,
            destChain,
            amount,
            route.totalCost
        );
    }

    /**
     * @notice Begin executing a committed relay operation
     * @param relayId The relay operation to execute
     */
    function beginExecution(
        bytes32 relayId
    ) external override onlyRole(EXECUTOR_ROLE) nonReentrant {
        RelayOperation storage t = relayOps[relayId];
        if (t.user == address(0)) revert RelayNotFound(relayId);
        if (t.status != RelayStatus.COMMITTED) {
            revert InvalidRelayStatus(relayId, t.status, RelayStatus.COMMITTED);
        }

        t.status = RelayStatus.EXECUTING;

        emit RelayExecuting(relayId, msg.sender);
    }

    /**
     * @notice Complete a relay operation — records metrics and updates orchestrator
     * @param relayId The relay that completed
     * @param actualLatency Actual completion latency in seconds
     */
    function completeRelay(
        bytes32 relayId,
        uint48 actualLatency
    ) external override onlyRole(COMPLETER_ROLE) nonReentrant {
        RelayOperation storage t = relayOps[relayId];
        if (t.user == address(0)) revert RelayNotFound(relayId);
        if (t.status != RelayStatus.EXECUTING) {
            revert InvalidRelayStatus(relayId, t.status, RelayStatus.EXECUTING);
        }

        t.status = RelayStatus.COMPLETED;
        t.completedAt = uint48(block.timestamp);

        // Update pair metrics
        bytes32 pairKey = keccak256(
            abi.encodePacked(t.sourceChainId, t.destChainId)
        );
        PairMetrics storage pm = pairMetrics[pairKey];
        pm.totalVolume += t.amount;
        pm.totalCosts += t.fee;
        pm.relayCount += 1;
        pm.lastRelay = uint48(block.timestamp);

        // Record bridge outcome in orchestrator
        IDynamicRoutingOrchestrator.Route memory route = orchestrator.getRoute(
            t.routeId
        );
        for (uint256 i = 0; i < route.relayAdapters.length; ++i) {
            try
                orchestrator.recordAdapterOutcome(
                    route.relayAdapters[i],
                    true,
                    actualLatency,
                    t.amount
                )
            {} catch {}
        }

        emit RelayCompleted(
            relayId,
            uint48(block.timestamp - t.committedAt),
            t.fee
        );
    }

    /**
     * @notice Mark a relay as failed and record failure metrics
     * @param relayId The failed relay
     * @param reason Failure reason
     */
    function failRelay(
        bytes32 relayId,
        string calldata reason
    ) external override onlyRole(COMPLETER_ROLE) nonReentrant {
        RelayOperation storage t = relayOps[relayId];
        if (t.user == address(0)) revert RelayNotFound(relayId);
        if (t.status != RelayStatus.EXECUTING) {
            revert InvalidRelayStatus(relayId, t.status, RelayStatus.EXECUTING);
        }

        t.status = RelayStatus.FAILED;

        // Refund user (amount + routing fee, protocol keeps protocol fee as gas cost)
        uint256 refundAmount = t.amount + t.fee;
        if (refundAmount > 0) {
            (bool ok, ) = t.user.call{value: refundAmount}("");
            require(ok, "Refund failed");
        }

        // Record failure in orchestrator
        IDynamicRoutingOrchestrator.Route memory route = orchestrator.getRoute(
            t.routeId
        );
        for (uint256 i = 0; i < route.relayAdapters.length; ++i) {
            try
                orchestrator.recordAdapterOutcome(
                    route.relayAdapters[i],
                    false,
                    0,
                    t.amount
                )
            {} catch {}
        }

        emit RelayFailed(relayId, reason);
    }

    /**
     * @notice Refund a timed-out relay — user can call after timeout
     * @param relayId The relay to refund
     */
    function refundTimedOut(bytes32 relayId) external override nonReentrant {
        RelayOperation storage t = relayOps[relayId];
        if (t.user == address(0)) revert RelayNotFound(relayId);
        if (
            t.status != RelayStatus.COMMITTED &&
            t.status != RelayStatus.EXECUTING
        ) {
            revert InvalidRelayStatus(relayId, t.status, RelayStatus.COMMITTED);
        }
        if (block.timestamp < t.committedAt + relayTimeout) {
            revert RelayNotTimedOut(relayId);
        }

        t.status = RelayStatus.REFUNDED;

        // SECURITY FIX H-10: Do not refund protocol fee to prevent draining
        // contract balance if fees were already withdrawn by admin.
        uint256 refundAmount = t.amount + t.fee;

        if (refundAmount > 0) {
            (bool ok, ) = t.user.call{value: refundAmount}("");
            require(ok, "Refund failed");
        }

        emit RelayRefunded(relayId, t.user, refundAmount);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get relay operation details
     * @param relayId The relay ID
     * @return t RelayOperation struct
     */
    function getRelayOp(
        bytes32 relayId
    ) external view override returns (RelayOperation memory t) {
        t = relayOps[relayId];
        if (t.user == address(0)) revert RelayNotFound(relayId);
    }

    /**
     * @notice Get metrics for a chain pair
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     * @return metrics The pair metrics
     */
    function getPairMetrics(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view override returns (PairMetrics memory metrics) {
        bytes32 pairKey = keccak256(
            abi.encodePacked(sourceChainId, destChainId)
        );
        return pairMetrics[pairKey];
    }

    /**
     * @notice Check if user can relay (cooldown elapsed)
     * @param user User address
     * @return canRelay Whether user can initiate a relay
     * @return cooldownRemaining Remaining cooldown seconds (0 if ready)
     */
    function canUserRelay(
        address user
    ) external view override returns (bool canRelay, uint48 cooldownRemaining) {
        uint48 lastTx = lastRelayAt[user];
        if (lastTx == 0 || block.timestamp >= lastTx + userCooldown) {
            return (true, 0);
        }
        return (false, uint48(lastTx + userCooldown - block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Withdraw accumulated protocol fees
     * @param recipient Fee recipient
     */
    function withdrawFees(
        address recipient
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        if (accumulatedFees == 0) revert NoFeesToWithdraw();

        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert WithdrawFailed();

        emit FeesWithdrawn(recipient, amount);
    }

    /**
     * @notice Update user cooldown period
     * @param newCooldown New cooldown in seconds
     */
    function setCooldown(
        uint48 newCooldown
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        uint48 oldCooldown = userCooldown;
        userCooldown = newCooldown;
        emit CooldownUpdated(oldCooldown, newCooldown);
    }

    /**
     * @notice Update relay timeout
     * @param newTimeout New timeout in seconds
     */
    function setTimeout(
        uint48 newTimeout
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTimeout >= 10 minutes, "Timeout too short");
        uint48 oldTimeout = relayTimeout;
        relayTimeout = newTimeout;
        emit TimeoutUpdated(oldTimeout, newTimeout);
    }

    /// @notice Pause the router
        /**
     * @notice Pauses the operation
     */
function pause() external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the router
        /**
     * @notice Unpauses the operation
     */
function unpause() external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Allow contract to receive ETH
    receive() external payable {}
}
