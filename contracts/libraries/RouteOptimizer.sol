// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDynamicRoutingOrchestrator} from "../interfaces/IDynamicRoutingOrchestrator.sol";

/**
 * @title RouteOptimizer
 * @author Soul Protocol
 * @notice Pure math library for multi-factor route scoring and optimization
 * @dev Used by DynamicRoutingOrchestrator and LiquidityAwareRouter to calculate
 *      composite route scores from cost, speed, reliability, and security metrics.
 *
 *      Scoring formula:
 *        score = (costScore * costWeight + speedScore * speedWeight
 *                + reliabilityScore * reliabilityWeight + securityScore * securityWeight) / BPS
 *        - Speed-priority bonus: +10% to speed weight, -10% from cost weight
 *        - Multi-hop penalty: -5% from final score
 *
 *      All scores and weights are in basis points (0-10000).
 */
library RouteOptimizer {
    /// @notice Basis points denominator
    uint16 internal constant BPS = 10_000;

    /// @notice Multi-hop penalty in bps (5%)
    uint16 internal constant MULTI_HOP_PENALTY_BPS = 500;

    /// @notice Speed priority bonus shift in bps (10%)
    uint16 internal constant SPEED_PRIORITY_SHIFT_BPS = 1000;

    /// @notice Configurable scoring weights (must sum to BPS)
    struct ScoringWeights {
        uint16 costWeight; // Weight for cost factor
        uint16 speedWeight; // Weight for speed factor
        uint16 reliabilityWeight; // Weight for reliability factor
        uint16 securityWeight; // Weight for security factor
    }

    /**
     * @notice Calculate a composite route score from individual factor scores
     * @param weights Scoring weights (must sum to 10000)
     * @param costScore Cost score (0-10000, higher = cheaper)
     * @param speedScore Speed score (0-10000, higher = faster)
     * @param reliabilityScore Reliability score (0-10000, higher = more reliable)
     * @param securityScore Security score (0-10000, higher = more secure)
     * @param speedPriority Whether to apply speed priority bonus
     * @param isMultiHop Whether to apply multi-hop penalty
     * @return score Composite score (0-10000)
     */
    function calculateScore(
        ScoringWeights memory weights,
        uint16 costScore,
        uint16 speedScore,
        uint16 reliabilityScore,
        uint16 securityScore,
        bool speedPriority,
        bool isMultiHop
    ) internal pure returns (uint16 score) {
        uint16 cw = weights.costWeight;
        uint16 sw = weights.speedWeight;
        uint16 rw = weights.reliabilityWeight;
        uint16 secw = weights.securityWeight;

        // Speed priority: shift weight from cost to speed
        if (speedPriority) {
            uint16 shift = cw > SPEED_PRIORITY_SHIFT_BPS
                ? SPEED_PRIORITY_SHIFT_BPS
                : cw;
            cw -= shift;
            sw += shift;
        }

        // Weighted sum
        uint256 raw = (uint256(costScore) *
            cw +
            uint256(speedScore) *
            sw +
            uint256(reliabilityScore) *
            rw +
            uint256(securityScore) *
            secw) / BPS;

        score = raw > BPS ? BPS : uint16(raw);

        // Multi-hop penalty
        if (isMultiHop && score > MULTI_HOP_PENALTY_BPS) {
            score -= MULTI_HOP_PENALTY_BPS;
        } else if (isMultiHop) {
            score = 0;
        }
    }

    /**
     * @notice Calculate liquidity impact factor for fee adjustment
     * @dev Used to determine fee premium based on transfer size relative to pool
     * @param amount Transfer amount
     * @param availableLiquidity Pool available liquidity
     * @return impactBps Impact in bps (0 = no impact, up to BPS)
     */
    function calculateLiquidityImpact(
        uint256 amount,
        uint256 availableLiquidity
    ) internal pure returns (uint16 impactBps) {
        if (availableLiquidity == 0 || amount == 0) return 0;

        uint256 ratio = (amount * BPS) / availableLiquidity;

        // Quadratic impact: impact = ratio^2 / BPS
        // This creates a convex curve: small amounts have minimal impact,
        // large amounts relative to liquidity have exponential impact
        uint256 quadratic = (ratio * ratio) / BPS;

        return quadratic > BPS ? BPS : uint16(quadratic);
    }

    /**
     * @notice Estimate settlement time based on hop count and average latencies
     * @param hopLatencies Array of per-hop average latencies (seconds)
     * @return totalTime Total estimated settlement time
     */
    function estimateMultiHopTime(
        uint48[] memory hopLatencies
    ) internal pure returns (uint48 totalTime) {
        for (uint256 i = 0; i < hopLatencies.length; ++i) {
            totalTime += hopLatencies[i];
        }
        // Add 10% overhead per additional hop (sequential processing)
        if (hopLatencies.length > 1) {
            totalTime += uint48(
                (uint256(totalTime) * (hopLatencies.length - 1) * 1000) / BPS
            );
        }
    }

    /**
     * @notice Calculate combined success probability for multi-hop route
     * @param hopProbabilities Array of per-hop success probabilities (bps)
     * @return combinedProbability Combined probability (bps)
     */
    function combineProbabilities(
        uint16[] memory hopProbabilities
    ) internal pure returns (uint16 combinedProbability) {
        if (hopProbabilities.length == 0) return 0;

        uint256 combined = uint256(hopProbabilities[0]);
        for (uint256 i = 1; i < hopProbabilities.length; ++i) {
            combined = (combined * uint256(hopProbabilities[i])) / BPS;
        }

        return combined > BPS ? BPS : uint16(combined);
    }

    /**
     * @notice Normalize a raw value to a 0-10000 bps score (inverse: lower raw = higher score)
     * @param value The raw value
     * @param minValue Minimum expected value (maps to 10000)
     * @param maxValue Maximum expected value (maps to 0)
     * @return score Normalized score in bps
     */
    function normalizeInverse(
        uint256 value,
        uint256 minValue,
        uint256 maxValue
    ) internal pure returns (uint16 score) {
        if (value <= minValue) return BPS;
        if (value >= maxValue) return 0;

        uint256 range = maxValue - minValue;
        uint256 position = value - minValue;

        return uint16(BPS - (position * BPS) / range);
    }

    /**
     * @notice Normalize a raw value to a 0-10000 bps score (direct: higher raw = higher score)
     * @param value The raw value
     * @param minValue Minimum expected value (maps to 0)
     * @param maxValue Maximum expected value (maps to 10000)
     * @return score Normalized score in bps
     */
    function normalizeDirect(
        uint256 value,
        uint256 minValue,
        uint256 maxValue
    ) internal pure returns (uint16 score) {
        if (value <= minValue) return 0;
        if (value >= maxValue) return BPS;

        uint256 range = maxValue - minValue;
        uint256 position = value - minValue;

        return uint16((position * BPS) / range);
    }
}
