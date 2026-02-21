// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title RelayerHealthMonitor
 * @author Soul Protocol
 * @notice Tracks performance metrics for relayers to incentivize reliability
 */
contract RelayerHealthMonitor is AccessControl {
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    struct RelayerStats {
        uint256 successfulRelays;
        uint256 failedRelays;
        uint256 totalLatency; // Cumulative latency in seconds
        uint256 lastSeen; // Timestamp of last activity
        uint256 penaltyPoints; // Administrative penalties
        bool isActive;
    }

    mapping(address => RelayerStats) public relayerStats;
    address[] public knownRelayers;

    event RelayerRegistered(address indexed relayer);
    event PerformanceRecorded(
        address indexed relayer,
        bool success,
        uint256 latency
    );
    event PenaltyApplied(
        address indexed relayer,
        uint256 points,
        string reason
    );

    /// @notice Deploy the health monitor and grant admin roles
    /// @param _admin Address receiving DEFAULT_ADMIN_ROLE and GOVERNANCE_ROLE
    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(GOVERNANCE_ROLE, _admin);
    }

    /**
     * @notice Register a new relayer for monitoring
     */
    function registerRelayer(
        address _relayer
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (!relayerStats[_relayer].isActive) {
            relayerStats[_relayer].isActive = true;
            knownRelayers.push(_relayer);
            emit RelayerRegistered(_relayer);
        }
    }

    /**
     * @notice Record a successful relay operation
     * @param _relayer The relayer address
     * @param _latency Latency in seconds (time since request)
     */
    function recordSuccess(
        address _relayer,
        uint256 _latency
    ) external onlyRole(ROUTER_ROLE) {
        RelayerStats storage stats = relayerStats[_relayer];
        if (!stats.isActive) return;

        stats.successfulRelays++;
        stats.totalLatency += _latency;
        stats.lastSeen = block.timestamp;

        emit PerformanceRecorded(_relayer, true, _latency);
    }

    /**
     * @notice Record a failed relay operation
     * @param _relayer The relayer address
     */
    function reportFailure(address _relayer) external onlyRole(ROUTER_ROLE) {
        RelayerStats storage stats = relayerStats[_relayer];
        if (!stats.isActive) return;

        stats.failedRelays++;
        stats.lastSeen = block.timestamp;

        emit PerformanceRecorded(_relayer, false, 0);
    }

    /**
     * @notice Apply penalty points to a relayer (e.g. for downtime or censorship)
     */
    function penalize(
        address _relayer,
        uint256 _points,
        string calldata _reason
    ) external onlyRole(GOVERNANCE_ROLE) {
        relayerStats[_relayer].penaltyPoints += _points;
        emit PenaltyApplied(_relayer, _points, _reason);
    }

    /**
     * @notice Calculate a health score (0-100) for a relayer
     * @dev Simple formula: Base 100 - FailureRate - LatencyPenalty - AdminPenalty
     */
    function getHealthScore(address _relayer) external view returns (uint256) {
        RelayerStats memory stats = relayerStats[_relayer];
        if (!stats.isActive) return 0;
        if (stats.successfulRelays + stats.failedRelays == 0) return 50; // Neutral start

        uint256 totalOps = stats.successfulRelays + stats.failedRelays;
        uint256 failureRate = (stats.failedRelays * 100) / totalOps;

        // Average latency penalty: 1 point per second over 30s avg
        uint256 avgLatency = stats.successfulRelays > 0
            ? stats.totalLatency / stats.successfulRelays
            : 0;
        uint256 latencyPenalty = avgLatency > 30 ? avgLatency - 30 : 0;
        if (latencyPenalty > 20) latencyPenalty = 20; // Cap latency penalty

        uint256 deductions = failureRate + latencyPenalty + stats.penaltyPoints;

        if (deductions >= 100) return 0;
        return 100 - deductions;
    }
}
