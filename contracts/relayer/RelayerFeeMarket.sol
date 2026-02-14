// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RelayerFeeMarket
 * @author Soul Protocol
 * @notice Dynamic fee market for cross-chain relay pricing
 * @dev Implements an EIP-1559-style base fee mechanism with competitive relay auctions.
 *      Relayers bid to service cross-chain proof relay requests. Fees adjust dynamically
 *      based on network congestion (relay utilization rate).
 *
 * FEE MECHANISM:
 * 1. Base Fee: Adjusts per-block based on utilization (EIP-1559 style)
 *    - If utilization > TARGET: baseFee *= (1 + delta)
 *    - If utilization < TARGET: baseFee *= (1 - delta)
 * 2. Priority Fee: User-set tip to incentivize faster relay
 * 3. Relay Auction: For high-value transfers, sealed-bid first-price auction
 *
 * LIFECYCLE:
 *   User submits relay request with maxFee → relayer claims request →
 *   relayer completes relay → relayer collects effective fee
 *
 * @custom:security-contact security@soul.network
 */
contract RelayerFeeMarket is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("RELAYER_ROLE")
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A relay request submitted by a user
    struct RelayRequest {
        bytes32 requestId;
        bytes32 sourceChainId;
        bytes32 destChainId;
        address requester;
        uint256 maxFee; // Maximum fee user is willing to pay
        uint256 priorityFee; // User tip above base fee
        uint256 submittedAt;
        uint256 deadline; // Must be relayed before this timestamp
        bytes32 proofId; // Proof to relay
        RequestStatus status;
        address claimedBy; // Relayer who claimed this request
        uint256 claimedAt;
        uint256 effectiveFee; // Actual fee paid
    }

    enum RequestStatus {
        PENDING,
        CLAIMED,
        COMPLETED,
        EXPIRED,
        CANCELLED
    }

    /// @notice Fee parameters for a route
    struct RouteFeeConfig {
        uint256 baseFee; // Current base fee (adjusts dynamically)
        uint256 minBaseFee; // Floor base fee
        uint256 maxBaseFee; // Ceiling base fee
        uint256 targetUtilization; // Target relay rate (per epoch, basis points)
        uint256 currentUtilization; // Current epoch utilization
        uint256 epochRelays; // Relays in current epoch
        uint256 lastEpochUpdate; // Last epoch start timestamp
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fee epoch duration (1 hour)
    uint256 public constant EPOCH_DURATION = 1 hours;

    /// @notice Maximum relays per epoch before fee spike
    uint256 public constant MAX_EPOCH_RELAYS = 1000;

    /// @notice Target utilization (50% = 5000 basis points)
    uint256 public constant DEFAULT_TARGET_UTILIZATION = 5000;

    /// @notice Base fee adjustment speed (12.5% per epoch, matching EIP-1559)
    uint256 public constant FEE_ADJUSTMENT_BPS = 1250;

    /// @notice Default minimum base fee (0.0001 ETH)
    uint256 public constant DEFAULT_MIN_BASE_FEE = 0.0001 ether;

    /// @notice Default maximum base fee (1 ETH)
    uint256 public constant DEFAULT_MAX_BASE_FEE = 1 ether;

    /// @notice Relay claim timeout (relayer must complete within this time)
    uint256 public constant CLAIM_TIMEOUT = 30 minutes;

    /// @notice Default request deadline (4 hours from submission)
    uint256 public constant DEFAULT_DEADLINE = 4 hours;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Fee token (SOUL token or ETH)
    IERC20 public immutable feeToken;

    /// @notice Route fee configurations (sourceChainId => destChainId => config)
    mapping(bytes32 => mapping(bytes32 => RouteFeeConfig)) public routeFees;

    /// @notice Relay requests (requestId => request)
    mapping(bytes32 => RelayRequest) public requests;

    /// @notice Pending request IDs (for enumeration)
    bytes32[] public pendingRequests;

    /// @notice Accumulated protocol fees
    uint256 public protocolFees;

    /// @notice Protocol fee percentage (basis points)
    uint256 public protocolFeeBps = 500; // 5%

    /// @notice Total relays completed
    uint256 public totalRelaysCompleted;

    /// @notice Total fees collected
    uint256 public totalFeesCollected;

    /// @notice Request nonce
    uint256 public requestNonce;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event RelayRequestSubmitted(
        bytes32 indexed requestId,
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        address requester,
        uint256 maxFee
    );

    event RelayRequestClaimed(
        bytes32 indexed requestId,
        address indexed relayer
    );

    event RelayCompleted(
        bytes32 indexed requestId,
        address indexed relayer,
        uint256 effectiveFee
    );

    event RelayRequestExpired(bytes32 indexed requestId);
    event RelayRequestCancelled(bytes32 indexed requestId);
    event BaseFeeUpdated(
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        uint256 newBaseFee
    );
    event ProtocolFeeWithdrawn(uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error RequestNotFound();
    error RequestNotPending();
    error RequestExpired();
    error RequestAlreadyClaimed();
    error ClaimTimeout();
    error InsufficientFee();
    error NotRequester();
    error NotClaimedRelayer();
    error RouteNotActive();
    error ZeroAddress();
    error InvalidFee();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _feeToken) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        feeToken = IERC20(_feeToken);
    }

    /*//////////////////////////////////////////////////////////////
                       USER-FACING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a relay request
    /// @param sourceChainId Source chain universal ID
    /// @param destChainId Destination chain universal ID
    /// @param proofId The proof to be relayed
    /// @param maxFee Maximum fee willing to pay
    /// @param priorityFee Priority tip above base fee
    /// @param deadline Request deadline (0 = default)
    /// @return requestId The relay request identifier
    function submitRelayRequest(
        bytes32 sourceChainId,
        bytes32 destChainId,
        bytes32 proofId,
        uint256 maxFee,
        uint256 priorityFee,
        uint256 deadline
    ) external nonReentrant returns (bytes32 requestId) {
        RouteFeeConfig storage routeConfig = routeFees[sourceChainId][
            destChainId
        ];
        if (!routeConfig.active) revert RouteNotActive();

        // Update base fee for the epoch
        _updateBaseFee(routeConfig);

        // Ensure max fee covers base fee
        uint256 effectiveBaseFee = routeConfig.baseFee;
        if (maxFee < effectiveBaseFee) revert InsufficientFee();

        // Generate request ID
        requestId = keccak256(
            abi.encodePacked(
                sourceChainId,
                destChainId,
                msg.sender,
                requestNonce,
                block.timestamp
            )
        );

        uint256 effectiveDeadline = deadline > 0
            ? deadline
            : block.timestamp + DEFAULT_DEADLINE;

        // Escrow the max fee
        feeToken.safeTransferFrom(msg.sender, address(this), maxFee);

        requests[requestId] = RelayRequest({
            requestId: requestId,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            requester: msg.sender,
            maxFee: maxFee,
            priorityFee: priorityFee,
            submittedAt: block.timestamp,
            deadline: effectiveDeadline,
            proofId: proofId,
            status: RequestStatus.PENDING,
            claimedBy: address(0),
            claimedAt: 0,
            effectiveFee: 0
        });

        pendingRequests.push(requestId);
        unchecked {
            ++requestNonce;
        }

        emit RelayRequestSubmitted(
            requestId,
            sourceChainId,
            destChainId,
            msg.sender,
            maxFee
        );
    }

    /// @notice Claim a relay request (relayer)
    /// @param requestId The request to claim
    function claimRelayRequest(
        bytes32 requestId
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        RelayRequest storage request = requests[requestId];
        if (request.requester == address(0)) revert RequestNotFound();
        if (request.status != RequestStatus.PENDING) revert RequestNotPending();
        if (block.timestamp > request.deadline) revert RequestExpired();

        request.status = RequestStatus.CLAIMED;
        request.claimedBy = msg.sender;
        request.claimedAt = block.timestamp;

        emit RelayRequestClaimed(requestId, msg.sender);
    }

    /// @notice Complete a relay and collect fee (relayer)
    /// @param requestId The completed request
    function completeRelay(
        bytes32 requestId
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        RelayRequest storage request = requests[requestId];
        if (request.claimedBy != msg.sender) revert NotClaimedRelayer();
        if (request.status != RequestStatus.CLAIMED) revert RequestNotPending();
        if (block.timestamp > request.claimedAt + CLAIM_TIMEOUT)
            revert ClaimTimeout();

        RouteFeeConfig storage routeConfig = routeFees[request.sourceChainId][
            request.destChainId
        ];

        // Calculate effective fee: baseFee + priorityFee (capped at maxFee)
        uint256 effectiveFee = routeConfig.baseFee + request.priorityFee;
        if (effectiveFee > request.maxFee) {
            effectiveFee = request.maxFee;
        }

        // Protocol cut
        uint256 protocolCut = (effectiveFee * protocolFeeBps) / 10_000;
        uint256 relayerPayout = effectiveFee - protocolCut;
        uint256 refund = request.maxFee - effectiveFee;

        // Update state
        request.status = RequestStatus.COMPLETED;
        request.effectiveFee = effectiveFee;
        protocolFees += protocolCut;

        // Track epoch utilization
        routeConfig.epochRelays += 1;

        unchecked {
            ++totalRelaysCompleted;
            totalFeesCollected += effectiveFee;
        }

        // Pay relayer
        feeToken.safeTransfer(msg.sender, relayerPayout);

        // Refund excess to requester
        if (refund > 0) {
            feeToken.safeTransfer(request.requester, refund);
        }

        emit RelayCompleted(requestId, msg.sender, effectiveFee);
    }

    /// @notice Cancel a pending relay request (requester only)
    function cancelRelayRequest(bytes32 requestId) external nonReentrant {
        RelayRequest storage request = requests[requestId];
        if (request.requester != msg.sender) revert NotRequester();
        if (request.status != RequestStatus.PENDING) revert RequestNotPending();

        request.status = RequestStatus.CANCELLED;

        // Full refund
        feeToken.safeTransfer(msg.sender, request.maxFee);

        emit RelayRequestCancelled(requestId);
    }

    /// @notice Expire a stale request (anyone can call)
    function expireRequest(bytes32 requestId) external nonReentrant {
        RelayRequest storage request = requests[requestId];
        if (request.requester == address(0)) revert RequestNotFound();
        if (
            request.status == RequestStatus.COMPLETED ||
            request.status == RequestStatus.CANCELLED
        ) {
            revert RequestNotPending();
        }

        bool canExpire = block.timestamp > request.deadline;
        // Also expire if claimed but not completed within CLAIM_TIMEOUT
        if (request.status == RequestStatus.CLAIMED) {
            canExpire =
                canExpire ||
                (block.timestamp > request.claimedAt + CLAIM_TIMEOUT);
        }

        require(canExpire, "Not expired yet");

        request.status = RequestStatus.EXPIRED;

        // Refund to requester
        feeToken.safeTransfer(request.requester, request.maxFee);

        emit RelayRequestExpired(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                         FEE QUERIES
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current base fee for a route
    /// @param sourceChainId The source chain identifier
    /// @param destChainId The destination chain identifier
    /// @return The current base fee in fee-token units
    function getBaseFee(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external view returns (uint256) {
        return routeFees[sourceChainId][destChainId].baseFee;
    }

    /// @notice Estimate total fee for a relay
    /// @param sourceChainId The source chain identifier
    /// @param destChainId The destination chain identifier
    /// @param priorityFee Additional priority fee offered by the requester
    /// @return totalFee The total fee (base + priority)
    /// @return baseFee The current base fee component
    function estimateFee(
        bytes32 sourceChainId,
        bytes32 destChainId,
        uint256 priorityFee
    ) external view returns (uint256 totalFee, uint256 baseFee) {
        RouteFeeConfig storage config = routeFees[sourceChainId][destChainId];
        baseFee = config.baseFee;
        totalFee = baseFee + priorityFee;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize fee config for a route
    /// @param sourceChainId The source chain identifier
    /// @param destChainId The destination chain identifier
    /// @param initialBaseFee The starting base fee for this route
    function initializeRoute(
        bytes32 sourceChainId,
        bytes32 destChainId,
        uint256 initialBaseFee
    ) external onlyRole(OPERATOR_ROLE) {
        routeFees[sourceChainId][destChainId] = RouteFeeConfig({
            baseFee: initialBaseFee,
            minBaseFee: DEFAULT_MIN_BASE_FEE,
            maxBaseFee: DEFAULT_MAX_BASE_FEE,
            targetUtilization: DEFAULT_TARGET_UTILIZATION,
            currentUtilization: 0,
            epochRelays: 0,
            lastEpochUpdate: block.timestamp,
            active: true
        });
    }

    /// @notice Update protocol fee percentage
    /// @param _bps The new protocol fee in basis points (max 1000 = 10%)
    function setProtocolFeeBps(uint256 _bps) external onlyRole(OPERATOR_ROLE) {
        require(_bps <= 1000, "Max 10%");
        protocolFeeBps = _bps;
    }

    /// @notice Withdraw accumulated protocol fees
    /// @param to The recipient address for the withdrawn fees
    function withdrawProtocolFees(
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = protocolFees;
        protocolFees = 0;
        feeToken.safeTransfer(to, amount);
        emit ProtocolFeeWithdrawn(amount);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the base fee based on epoch utilization (EIP-1559 style)
    function _updateBaseFee(RouteFeeConfig storage config) internal {
        if (block.timestamp < config.lastEpochUpdate + EPOCH_DURATION) return;

        // Calculate utilization ratio for the completed epoch
        uint256 utilization = (config.epochRelays * 10_000) / MAX_EPOCH_RELAYS;
        config.currentUtilization = utilization;

        uint256 newBaseFee = config.baseFee;

        if (utilization > config.targetUtilization) {
            // Over target: increase base fee
            uint256 delta = (newBaseFee * FEE_ADJUSTMENT_BPS) / 10_000;
            if (delta == 0) delta = 1;
            newBaseFee += delta;
        } else if (utilization < config.targetUtilization) {
            // Under target: decrease base fee
            uint256 delta = (newBaseFee * FEE_ADJUSTMENT_BPS) / 10_000;
            if (delta == 0) delta = 1;
            if (newBaseFee > delta) {
                newBaseFee -= delta;
            } else {
                newBaseFee = config.minBaseFee;
            }
        }

        // Clamp to bounds
        if (newBaseFee < config.minBaseFee) newBaseFee = config.minBaseFee;
        if (newBaseFee > config.maxBaseFee) newBaseFee = config.maxBaseFee;

        config.baseFee = newBaseFee;
        config.epochRelays = 0;
        config.lastEpochUpdate = block.timestamp;

        emit BaseFeeUpdated(bytes32(0), bytes32(0), newBaseFee);
    }
}
