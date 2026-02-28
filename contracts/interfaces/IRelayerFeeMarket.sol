// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IRelayerFeeMarket
 * @author ZASEON
 * @notice Interface for EIP-1559-style dynamic relay fee market
 */
interface IRelayerFeeMarket {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum RequestStatus {
        PENDING,
        CLAIMED,
        COMPLETED,
        EXPIRED,
        CANCELLED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RelayRequest {
        bytes32 requestId;
        bytes32 sourceChainId;
        bytes32 destChainId;
        address requester;
        uint256 maxFee;
        uint256 priorityFee;
        uint256 submittedAt;
        uint256 deadline;
        bytes32 proofId;
        RequestStatus status;
        address claimedBy;
        uint256 claimedAt;
        uint256 effectiveFee;
    }

    struct RouteFeeConfig {
        uint256 baseFee;
        uint256 minBaseFee;
        uint256 maxBaseFee;
        uint256 targetUtilization;
        uint256 currentUtilization;
        uint256 epochRelays;
        uint256 lastEpochUpdate;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new relay request is submitted by a requester
    /// @param requestId The unique request identifier
    /// @param sourceChainId The source chain identifier
    /// @param destChainId The destination chain identifier
    /// @param requester The address submitting the request
    /// @param maxFee The maximum fee the requester is willing to pay
    event RelayRequestSubmitted(
        bytes32 indexed requestId,
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        address requester,
        uint256 maxFee
    );

    /// @notice Emitted when a relayer claims a pending relay request
    /// @param requestId The unique request identifier
    /// @param relayer The relayer address that claimed the request
    event RelayRequestClaimed(
        bytes32 indexed requestId,
        address indexed relayer
    );
    /// @notice Emitted when a relay is completed and fees are distributed
    /// @param requestId The unique request identifier
    /// @param relayer The relayer that completed the relay
    /// @param effectiveFee The actual fee paid after EIP-1559 calculation
    event RelayCompleted(
        bytes32 indexed requestId,
        address indexed relayer,
        uint256 effectiveFee
    );
    /// @notice Emitted when a relay request expires without being fulfilled
    /// @param requestId The expired request identifier
    event RelayRequestExpired(bytes32 indexed requestId);
    /// @notice Emitted when a requester cancels their relay request
    /// @param requestId The cancelled request identifier
    event RelayRequestCancelled(bytes32 indexed requestId);
    /// @notice Emitted when the base fee for a chain pair is updated via EIP-1559 mechanism
    /// @param sourceChainId The source chain identifier
    /// @param destChainId The destination chain identifier
    /// @param newBaseFee The updated base fee
    event BaseFeeUpdated(
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        uint256 newBaseFee
    );
    /// @notice Emitted when accumulated protocol fees are withdrawn by the admin
    /// @param amount The amount of fees withdrawn
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
                       USER-FACING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function submitRelayRequest(
        bytes32 sourceChainId,
        bytes32 destChainId,
        bytes32 proofId,
        uint256 maxFee,
        uint256 priorityFee,
        uint256 deadline
    ) external returns (bytes32 requestId);

    function claimRelayRequest(bytes32 requestId) external;

    function completeRelay(bytes32 requestId) external;

    function cancelRelayRequest(bytes32 requestId) external;

    function expireRequest(bytes32 requestId) external;

    /*//////////////////////////////////////////////////////////////
                         FEE QUERIES
    //////////////////////////////////////////////////////////////*/

    function getBaseFee(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external view returns (uint256);

    function estimateFee(
        bytes32 sourceChainId,
        bytes32 destChainId,
        uint256 priorityFee
    ) external view returns (uint256 totalFee, uint256 baseFee);

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function initializeRoute(
        bytes32 sourceChainId,
        bytes32 destChainId,
        uint256 initialBaseFee
    ) external;

    function setProtocolFeeBps(uint256 _bps) external;

    function withdrawProtocolFees(address to) external;
}
