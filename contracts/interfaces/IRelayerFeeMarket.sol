// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title IRelayerFeeMarket
 * @author Soul Protocol
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
