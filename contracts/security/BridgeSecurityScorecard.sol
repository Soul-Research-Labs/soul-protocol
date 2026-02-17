// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BridgeSecurityScorecard
 * @notice Maintains security scores for bridge adapters based on various risk factors.
 * @dev Used by the protocol to determine if a bridge is safe to use for high-value transfers.
 */
contract BridgeSecurityScorecard is AccessControl {
    
    bytes32 public constant SCORE_ADMIN_ROLE = keccak256("SCORE_ADMIN_ROLE");

    struct SecurityScore {
        uint256 validatorDecentralization;  // 0-20 points
        uint256 economicSecurity;           // 0-20 points
        uint256 auditScore;                 // 0-20 points
        uint256 uptimeScore;                // 0-20 points
        uint256 incidentHistory;            // 0-20 points
        uint256 totalScore;                 // 0-100 points
        uint256 lastUpdated;
    }
    
    mapping(address => SecurityScore) public bridgeScores;
    uint256 public minimumSafeScore = 70;

    event ScoreUpdated(address indexed bridge, uint256 newScore);
    event MinimumSafeScoreUpdated(uint256 newMin);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SCORE_ADMIN_ROLE, admin);
    }

    /**
     * @notice Update the security score for a bridge adapter.
     * @param bridge The address of the bridge adapter.
     * @param decentralization Validator decentralization score (0-20).
     * @param economic Economic security score (0-20).
     * @param audit Audit quality score (0-20).
     * @param uptime Uptime reliability score (0-20).
     * @param history Incident history score (0-20, higher is better/safer).
     */
    function updateScore(
        address bridge,
        uint256 decentralization,
        uint256 economic,
        uint256 audit,
        uint256 uptime,
        uint256 history
    ) external onlyRole(SCORE_ADMIN_ROLE) {
        require(decentralization <= 20, "Score component > 20");
        require(economic <= 20, "Score component > 20");
        require(audit <= 20, "Score component > 20");
        require(uptime <= 20, "Score component > 20");
        require(history <= 20, "Score component > 20");

        uint256 total = decentralization + economic + audit + uptime + history;

        bridgeScores[bridge] = SecurityScore({
            validatorDecentralization: decentralization,
            economicSecurity: economic,
            auditScore: audit,
            uptimeScore: uptime,
            incidentHistory: history,
            totalScore: total,
            lastUpdated: block.timestamp
        });

        emit ScoreUpdated(bridge, total);
    }
    
    /**
     * @notice Check if a bridge is considered safe.
     * @param bridge The address of the bridge adapter.
     * @return bool True if total score >= minimumSafeScore.
     */
    function isBridgeSafe(address bridge) external view returns (bool) {
        return bridgeScores[bridge].totalScore >= minimumSafeScore;
    }

    /**
     * @notice Get the full score details for a bridge.
     */
    function getScore(address bridge) external view returns (SecurityScore memory) {
        return bridgeScores[bridge];
    }

    /**
     * @notice Update the minimum score required for a bridge to be considered safe.
     */
    function setMinimumSafeScore(uint256 newMin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMin <= 100, "Invalid score");
        minimumSafeScore = newMin;
        emit MinimumSafeScoreUpdated(newMin);
    }
}
