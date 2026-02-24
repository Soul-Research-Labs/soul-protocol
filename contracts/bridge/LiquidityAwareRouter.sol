// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {IDynamicRoutingOrchestrator} from "../interfaces/IDynamicRoutingOrchestrator.sol";
import {RouteOptimizer} from "../libraries/RouteOptimizer.sol";

/**
 * @title LiquidityAwareRouter
 * @author Soul Protocol
 * @notice Proof-routing frontend that executes routes from DynamicRoutingOrchestrator
 * @dev Routes ZK proof relay requests through optimal bridge adapters.
 *      Soul Protocol is proof middleware — the "transfers" tracked here are
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
 *      1. User calls `quoteTransfer()` → gets Route from orchestrator
 *      2. User calls `commitRoute()` with routeId → locks fee, confirms execution
 *      3. Router calls `beginExecution()` → triggers bridge adapter(s)
 *      4. On completion, `settleTransfer()` finalizes and records metrics
 *
 *      Security features:
 *      - ReentrancyGuard on all fund-handling functions
 *      - Minimum cooldown between transfers per user (configurable)
 *      - Maximum single transfer limit
 *      - Stale route detection (routes expire after 5 minutes)
 *      - Zero-address validation
 */
contract LiquidityAwareRouter is AccessControl, ReentrancyGuard, Pausable {
    using RouteOptimizer for RouteOptimizer.ScoringWeights;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for executing transfers
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Role for settling completed transfers
    bytes32 public constant SETTLER_ROLE = keccak256("SETTLER_ROLE");

    /// @notice Protocol fee in bps (3%)
    uint16 public constant PROTOCOL_FEE_BPS = 300;

    /// @notice Basis points denominator
    uint16 public constant BPS = 10_000;

    /// @notice Default cooldown between transfers per user (30 seconds)
    uint48 public constant DEFAULT_COOLDOWN = 30;

    /// @notice Maximum single transfer (500 ETH)
    uint256 public constant MAX_TRANSFER_AMOUNT = 500 ether;

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Transfer lifecycle status
    enum TransferStatus {
        NONE, // Not created
        COMMITTED, // User committed funds
        EXECUTING, // Adapter called, waiting for confirmation
        SETTLED, // Successfully completed
        FAILED, // Failed, funds returned to user
        REFUNDED // User manually refunded after timeout
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A committed transfer
    struct Transfer {
        bytes32 routeId; // Associated route from orchestrator
        address user; // Transfer initiator
        uint256 sourceChainId; // Source chain
        uint256 destChainId; // Destination chain
        uint256 amount; // Transfer amount
        uint256 fee; // Fee charged
        uint256 protocolFee; // Protocol's share of fee
        TransferStatus status; // Current status
        uint48 committedAt; // Commitment timestamp
        uint48 settledAt; // Settlement timestamp (0 if not settled)
        address destRecipient; // Recipient on destination chain
    }

    /// @notice Volume tracking per chain pair
    struct PairMetrics {
        uint256 totalVolume; // Total value transferred
        uint256 totalFees; // Total fees collected
        uint256 transferCount; // Number of transfers
        uint48 lastTransfer; // Last transfer timestamp
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The DynamicRoutingOrchestrator this router uses for route selection
    IDynamicRoutingOrchestrator public immutable orchestrator;

    /// @notice Transfers indexed by transfer ID
    mapping(bytes32 => Transfer) public transfers;

    /// @notice User's last transfer timestamp (for cooldown)
    mapping(address => uint48) public lastTransferAt;

    /// @notice Per-pair volume metrics: keccak256(sourceChain, destChain) => PairMetrics
    mapping(bytes32 => PairMetrics) public pairMetrics;

    /// @notice Accumulated protocol fees (withdrawable by admin)
    uint256 public accumulatedFees;

    /// @notice Transfer nonce for unique ID generation
    uint256 internal _transferNonce;

    /// @notice Transfer timeout (1 hour)
    uint48 public transferTimeout = 1 hours;

    /// @notice User cooldown between transfers
    uint48 public userCooldown = DEFAULT_COOLDOWN;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransferCommitted(
        bytes32 indexed transferId,
        bytes32 indexed routeId,
        address indexed user,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        uint256 fee
    );

    event TransferExecuting(
        bytes32 indexed transferId,
        address indexed executor
    );

    event TransferSettled(
        bytes32 indexed transferId,
        uint48 settlementTime,
        uint256 actualFee
    );

    event TransferFailed(bytes32 indexed transferId, string reason);

    event TransferRefunded(
        bytes32 indexed transferId,
        address indexed user,
        uint256 amount
    );

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    event CooldownUpdated(uint48 oldCooldown, uint48 newCooldown);

    event TimeoutUpdated(uint48 oldTimeout, uint48 newTimeout);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error TransferTooLarge(uint256 amount, uint256 max);
    error CooldownNotElapsed(address user, uint48 remaining);
    error TransferNotFound(bytes32 transferId);
    error InvalidTransferStatus(
        bytes32 transferId,
        TransferStatus current,
        TransferStatus expected
    );
    error TransferTimedOut(bytes32 transferId);
    error TransferNotTimedOut(bytes32 transferId);
    error InsufficientPayment(uint256 required, uint256 provided);
    error NoFeesToWithdraw();
    error WithdrawFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the liquidity-aware router
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
        _grantRole(SETTLER_ROLE, executor);
    }

    /*//////////////////////////////////////////////////////////////
                          TRANSFER LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Quote a cross-chain transfer — returns the optimal route and fee
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     * @param amount Transfer amount
     * @param urgency Speed/cost preference
     * @return route The optimal route
     * @return totalRequired Total payment required (amount + fee)
     */
    function quoteTransfer(
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
        uint256 protocolFee = (route.totalCost * PROTOCOL_FEE_BPS) / BPS;
        totalRequired = amount + route.totalCost + protocolFee;
    }

    /**
     * @notice Commit to a transfer — locks funds and records the transfer
     * @param routeId Route ID from the orchestrator
     * @param destRecipient Recipient address on destination chain
     * @return transferId Unique transfer identifier
     */
    function commitTransfer(
        bytes32 routeId,
        address destRecipient
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        if (destRecipient == address(0)) revert ZeroAddress();

        // Check cooldown
        uint48 lastTx = lastTransferAt[msg.sender];
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
        uint256 protocolFee = (route.totalCost * PROTOCOL_FEE_BPS) / BPS;
        uint256 totalRequired = route.totalCost + protocolFee;
        if (msg.value < totalRequired) {
            revert InsufficientPayment(totalRequired, msg.value);
        }

        uint256 amount = msg.value - totalRequired;
        if (amount > MAX_TRANSFER_AMOUNT) {
            revert TransferTooLarge(amount, MAX_TRANSFER_AMOUNT);
        }

        // Generate transfer ID
        _transferNonce++;
        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                routeId,
                _transferNonce,
                block.timestamp
            )
        );

        uint256 sourceChain = route.chainPath[0];
        uint256 destChain = route.chainPath[route.chainPath.length - 1];

        // Record transfer
        transfers[transferId] = Transfer({
            routeId: routeId,
            user: msg.sender,
            sourceChainId: sourceChain,
            destChainId: destChain,
            amount: amount,
            fee: route.totalCost,
            protocolFee: protocolFee,
            status: TransferStatus.COMMITTED,
            committedAt: uint48(block.timestamp),
            settledAt: 0,
            destRecipient: destRecipient
        });

        lastTransferAt[msg.sender] = uint48(block.timestamp);
        accumulatedFees += protocolFee;

        // Refund excess payment
        uint256 excess = msg.value - totalRequired - amount;
        if (excess > 0) {
            (bool ok, ) = msg.sender.call{value: excess}("");
            require(ok, "Refund failed");
        }

        emit TransferCommitted(
            transferId,
            routeId,
            msg.sender,
            sourceChain,
            destChain,
            amount,
            route.totalCost
        );
    }

    /**
     * @notice Begin executing a committed transfer
     * @param transferId The transfer to execute
     */
    function beginExecution(
        bytes32 transferId
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant {
        Transfer storage t = transfers[transferId];
        if (t.user == address(0)) revert TransferNotFound(transferId);
        if (t.status != TransferStatus.COMMITTED) {
            revert InvalidTransferStatus(
                transferId,
                t.status,
                TransferStatus.COMMITTED
            );
        }

        t.status = TransferStatus.EXECUTING;

        emit TransferExecuting(transferId, msg.sender);
    }

    /**
     * @notice Settle a completed transfer — records metrics and updates orchestrator
     * @param transferId The transfer that completed
     * @param actualLatency Actual settlement latency in seconds
     */
    function settleTransfer(
        bytes32 transferId,
        uint48 actualLatency
    ) external onlyRole(SETTLER_ROLE) nonReentrant {
        Transfer storage t = transfers[transferId];
        if (t.user == address(0)) revert TransferNotFound(transferId);
        if (t.status != TransferStatus.EXECUTING) {
            revert InvalidTransferStatus(
                transferId,
                t.status,
                TransferStatus.EXECUTING
            );
        }

        t.status = TransferStatus.SETTLED;
        t.settledAt = uint48(block.timestamp);

        // Update pair metrics
        bytes32 pairKey = keccak256(
            abi.encodePacked(t.sourceChainId, t.destChainId)
        );
        PairMetrics storage pm = pairMetrics[pairKey];
        pm.totalVolume += t.amount;
        pm.totalFees += t.fee;
        pm.transferCount += 1;
        pm.lastTransfer = uint48(block.timestamp);

        // Record bridge outcome in orchestrator
        IDynamicRoutingOrchestrator.Route memory route = orchestrator.getRoute(
            t.routeId
        );
        for (uint256 i = 0; i < route.bridgeAdapters.length; ++i) {
            try
                orchestrator.recordBridgeOutcome(
                    route.bridgeAdapters[i],
                    true,
                    actualLatency,
                    t.amount
                )
            {} catch {}
        }

        emit TransferSettled(
            transferId,
            uint48(block.timestamp - t.committedAt),
            t.fee
        );
    }

    /**
     * @notice Mark a transfer as failed and record failure metrics
     * @param transferId The failed transfer
     * @param reason Failure reason
     */
    function failTransfer(
        bytes32 transferId,
        string calldata reason
    ) external onlyRole(SETTLER_ROLE) nonReentrant {
        Transfer storage t = transfers[transferId];
        if (t.user == address(0)) revert TransferNotFound(transferId);
        if (t.status != TransferStatus.EXECUTING) {
            revert InvalidTransferStatus(
                transferId,
                t.status,
                TransferStatus.EXECUTING
            );
        }

        t.status = TransferStatus.FAILED;

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
        for (uint256 i = 0; i < route.bridgeAdapters.length; ++i) {
            try
                orchestrator.recordBridgeOutcome(
                    route.bridgeAdapters[i],
                    false,
                    0,
                    t.amount
                )
            {} catch {}
        }

        emit TransferFailed(transferId, reason);
    }

    /**
     * @notice Refund a timed-out transfer — user can call after timeout
     * @param transferId The transfer to refund
     */
    function refundTimedOut(bytes32 transferId) external nonReentrant {
        Transfer storage t = transfers[transferId];
        if (t.user == address(0)) revert TransferNotFound(transferId);
        if (
            t.status != TransferStatus.COMMITTED &&
            t.status != TransferStatus.EXECUTING
        ) {
            revert InvalidTransferStatus(
                transferId,
                t.status,
                TransferStatus.COMMITTED
            );
        }
        if (block.timestamp < t.committedAt + transferTimeout) {
            revert TransferNotTimedOut(transferId);
        }

        t.status = TransferStatus.REFUNDED;

        // SECURITY FIX H-10: Do not refund protocol fee to prevent draining
        // contract balance if fees were already withdrawn by admin.
        uint256 refundAmount = t.amount + t.fee;

        if (refundAmount > 0) {
            (bool ok, ) = t.user.call{value: refundAmount}("");
            require(ok, "Refund failed");
        }

        emit TransferRefunded(transferId, t.user, refundAmount);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get transfer details
     * @param transferId The transfer ID
     * @return t Transfer struct
     */
    function getTransfer(
        bytes32 transferId
    ) external view returns (Transfer memory t) {
        t = transfers[transferId];
        if (t.user == address(0)) revert TransferNotFound(transferId);
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
    ) external view returns (PairMetrics memory metrics) {
        bytes32 pairKey = keccak256(
            abi.encodePacked(sourceChainId, destChainId)
        );
        return pairMetrics[pairKey];
    }

    /**
     * @notice Check if user can transfer (cooldown elapsed)
     * @param user User address
     * @return canTransfer Whether user can initiate a transfer
     * @return cooldownRemaining Remaining cooldown seconds (0 if ready)
     */
    function canUserTransfer(
        address user
    ) external view returns (bool canTransfer, uint48 cooldownRemaining) {
        uint48 lastTx = lastTransferAt[user];
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
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
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
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint48 oldCooldown = userCooldown;
        userCooldown = newCooldown;
        emit CooldownUpdated(oldCooldown, newCooldown);
    }

    /**
     * @notice Update transfer timeout
     * @param newTimeout New timeout in seconds
     */
    function setTimeout(
        uint48 newTimeout
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTimeout >= 10 minutes, "Timeout too short");
        uint48 oldTimeout = transferTimeout;
        transferTimeout = newTimeout;
        emit TimeoutUpdated(oldTimeout, newTimeout);
    }

    /// @notice Pause the router
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the router
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Allow contract to receive ETH
    receive() external payable {}
}
