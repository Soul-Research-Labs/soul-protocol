// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RouteOptimizer} from "../../contracts/libraries/RouteOptimizer.sol";

contract RouteOptimizerTest is Test {
    // Default balanced weights
    RouteOptimizer.ScoringWeights internal defaultWeights;

    function setUp() public {
        defaultWeights = RouteOptimizer.ScoringWeights({
            costWeight: 3000,
            speedWeight: 2500,
            reliabilityWeight: 2500,
            securityWeight: 2000
        });
    }

    /*//////////////////////////////////////////////////////////////
                    CALCULATE SCORE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CalculateScore_AllPerfect() public view {
        uint16 score = RouteOptimizer.calculateScore(
            defaultWeights,
            10000, // max cost score
            10000, // max speed
            10000, // max reliability
            10000, // max security
            false, // no speed priority
            false // no multi-hop
        );

        // (10000*3000 + 10000*2500 + 10000*2500 + 10000*2000) / 10000 = 10000
        assertEq(score, 10000);
    }

    function test_CalculateScore_AllZero() public view {
        uint16 score = RouteOptimizer.calculateScore(
            defaultWeights,
            0,
            0,
            0,
            0,
            false,
            false
        );

        assertEq(score, 0);
    }

    function test_CalculateScore_BalancedMedium() public view {
        uint16 score = RouteOptimizer.calculateScore(
            defaultWeights,
            5000,
            5000,
            5000,
            5000,
            false,
            false
        );

        // (5000*3000 + 5000*2500 + 5000*2500 + 5000*2000) / 10000 = 5000
        assertEq(score, 5000);
    }

    function test_CalculateScore_SpeedPriorityShiftsWeight() public view {
        // Without speed priority
        uint16 normalScore = RouteOptimizer.calculateScore(
            defaultWeights,
            8000, // high cost score (cheap)
            4000, // low speed score
            7000,
            7000,
            false,
            false
        );

        // With speed priority (shifts 1000 bps from cost to speed)
        uint16 fastScore = RouteOptimizer.calculateScore(
            defaultWeights,
            8000,
            4000,
            7000,
            7000,
            true,
            false
        );

        // Speed priority with low speed and high cost should produce LOWER score
        // because we're shifting weight toward the weak factor (speed)
        assertTrue(fastScore < normalScore);
    }

    function test_CalculateScore_SpeedPriorityBenefitsHighSpeed() public view {
        uint16 normalScore = RouteOptimizer.calculateScore(
            defaultWeights,
            4000, // low cost score (expensive)
            9000, // high speed score
            7000,
            7000,
            false,
            false
        );

        uint16 fastScore = RouteOptimizer.calculateScore(
            defaultWeights,
            4000,
            9000,
            7000,
            7000,
            true,
            false
        );

        // Speed priority with high speed and low cost should produce HIGHER score
        assertTrue(fastScore > normalScore);
    }

    function test_CalculateScore_MultiHopPenalty() public view {
        uint16 directScore = RouteOptimizer.calculateScore(
            defaultWeights,
            8000,
            7000,
            9000,
            8000,
            false,
            false
        );

        uint16 multiHopScore = RouteOptimizer.calculateScore(
            defaultWeights,
            8000,
            7000,
            9000,
            8000,
            false,
            true
        );

        // Multi-hop should be exactly 500 bps less
        assertEq(multiHopScore, directScore - 500);
    }

    function test_CalculateScore_MultiHopPenaltyClampsToZero() public view {
        uint16 score = RouteOptimizer.calculateScore(
            defaultWeights,
            100, // terrible
            100,
            100,
            100,
            false,
            true // multi-hop penalty
        );

        // Raw score would be 100, - 500 penalty = underflow protection → 0
        assertEq(score, 0);
    }

    function test_CalculateScore_CappedAtBPS() public view {
        // Even with extreme weights, score should not exceed 10000
        RouteOptimizer.ScoringWeights memory w = RouteOptimizer.ScoringWeights({
            costWeight: 10000,
            speedWeight: 0,
            reliabilityWeight: 0,
            securityWeight: 0
        });

        uint16 score = RouteOptimizer.calculateScore(
            w,
            10000,
            10000,
            10000,
            10000,
            false,
            false
        );

        assertTrue(score <= 10000);
    }

    /*//////////////////////////////////////////////////////////////
                  LIQUIDITY IMPACT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_LiquidityImpact_Zero() public pure {
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(0, 1000 ether);
        assertEq(impact, 0);
    }

    function test_LiquidityImpact_ZeroLiquidity() public pure {
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(10 ether, 0);
        assertEq(impact, 0);
    }

    function test_LiquidityImpact_SmallAmount() public pure {
        // 1 ETH out of 1000 = 0.1% = 10 bps
        // Quadratic: 10^2 / 10000 = 0 bps (below 1)
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(
            1 ether,
            1000 ether
        );
        assertTrue(impact <= 100); // Should be very small
    }

    function test_LiquidityImpact_LargeAmount() public pure {
        // 500 ETH out of 1000 = 50% = 5000 bps
        // Quadratic: 5000^2 / 10000 = 2500 bps
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(
            500 ether,
            1000 ether
        );
        assertEq(impact, 2500);
    }

    function test_LiquidityImpact_FullLiquidity() public pure {
        // 1000 ETH out of 1000 = 100% = 10000 bps
        // Quadratic: 10000^2 / 10000 = 10000 bps = BPS cap
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(
            1000 ether,
            1000 ether
        );
        assertEq(impact, 10000);
    }

    function test_LiquidityImpact_OverLiquidity() public pure {
        // 2000 ETH out of 1000 = 200% = 20000 bps
        // Quadratic would overflow to 40000, capped at BPS
        uint16 impact = RouteOptimizer.calculateLiquidityImpact(
            2000 ether,
            1000 ether
        );
        assertEq(impact, 10000); // Capped
    }

    /*//////////////////////////////////////////////////////////////
                   MULTI-HOP TIME ESTIMATION
    //////////////////////////////////////////////////////////////*/

    function test_EstimateMultiHopTime_SingleHop() public pure {
        uint48[] memory latencies = new uint48[](1);
        latencies[0] = 60;

        uint48 time = RouteOptimizer.estimateMultiHopTime(latencies);
        assertEq(time, 60); // No overhead for single hop
    }

    function test_EstimateMultiHopTime_TwoHops() public pure {
        uint48[] memory latencies = new uint48[](2);
        latencies[0] = 60;
        latencies[1] = 30;

        uint48 time = RouteOptimizer.estimateMultiHopTime(latencies);
        // Base: 90, + 10% for 1 extra hop = 90 + 9 = 99
        assertEq(time, 99);
    }

    function test_EstimateMultiHopTime_ThreeHops() public pure {
        uint48[] memory latencies = new uint48[](3);
        latencies[0] = 60;
        latencies[1] = 30;
        latencies[2] = 45;

        uint48 time = RouteOptimizer.estimateMultiHopTime(latencies);
        // Base: 135, + 20% for 2 extra hops = 135 + 27 = 162
        assertEq(time, 162);
    }

    function test_EstimateMultiHopTime_Empty() public pure {
        uint48[] memory latencies = new uint48[](0);
        uint48 time = RouteOptimizer.estimateMultiHopTime(latencies);
        assertEq(time, 0);
    }

    /*//////////////////////////////////////////////////////////////
                  COMBINE PROBABILITIES
    //////////////////////////////////////////////////////////////*/

    function test_CombineProbabilities_Single() public pure {
        uint16[] memory probs = new uint16[](1);
        probs[0] = 9500;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        assertEq(combined, 9500);
    }

    function test_CombineProbabilities_Two() public pure {
        uint16[] memory probs = new uint16[](2);
        probs[0] = 9000;
        probs[1] = 8000;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        // 9000 * 8000 / 10000 = 7200
        assertEq(combined, 7200);
    }

    function test_CombineProbabilities_Three() public pure {
        uint16[] memory probs = new uint16[](3);
        probs[0] = 9000;
        probs[1] = 8000;
        probs[2] = 7000;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        // 9000 * 8000 / 10000 = 7200
        // 7200 * 7000 / 10000 = 5040
        assertEq(combined, 5040);
    }

    function test_CombineProbabilities_Empty() public pure {
        uint16[] memory probs = new uint16[](0);
        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        assertEq(combined, 0);
    }

    function test_CombineProbabilities_AllPerfect() public pure {
        uint16[] memory probs = new uint16[](2);
        probs[0] = 10000;
        probs[1] = 10000;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        assertEq(combined, 10000);
    }

    function test_CombineProbabilities_OneZero() public pure {
        uint16[] memory probs = new uint16[](2);
        probs[0] = 9000;
        probs[1] = 0;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        assertEq(combined, 0);
    }

    /*//////////////////////////////////////////////////////////////
                    NORMALIZE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_NormalizeInverse_AtMin() public pure {
        uint16 score = RouteOptimizer.normalizeInverse(10, 10, 100);
        assertEq(score, 10000);
    }

    function test_NormalizeInverse_AtMax() public pure {
        uint16 score = RouteOptimizer.normalizeInverse(100, 10, 100);
        assertEq(score, 0);
    }

    function test_NormalizeInverse_Middle() public pure {
        uint16 score = RouteOptimizer.normalizeInverse(55, 10, 100);
        assertEq(score, 5000);
    }

    function test_NormalizeInverse_BelowMin() public pure {
        uint16 score = RouteOptimizer.normalizeInverse(5, 10, 100);
        assertEq(score, 10000);
    }

    function test_NormalizeInverse_AboveMax() public pure {
        uint16 score = RouteOptimizer.normalizeInverse(200, 10, 100);
        assertEq(score, 0);
    }

    function test_NormalizeDirect_AtMin() public pure {
        uint16 score = RouteOptimizer.normalizeDirect(10, 10, 100);
        assertEq(score, 0);
    }

    function test_NormalizeDirect_AtMax() public pure {
        uint16 score = RouteOptimizer.normalizeDirect(100, 10, 100);
        assertEq(score, 10000);
    }

    function test_NormalizeDirect_Middle() public pure {
        uint16 score = RouteOptimizer.normalizeDirect(55, 10, 100);
        assertEq(score, 5000);
    }

    function test_NormalizeDirect_BelowMin() public pure {
        uint16 score = RouteOptimizer.normalizeDirect(5, 10, 100);
        assertEq(score, 0);
    }

    function test_NormalizeDirect_AboveMax() public pure {
        uint16 score = RouteOptimizer.normalizeDirect(200, 10, 100);
        assertEq(score, 10000);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_CalculateScore_BoundedOutput(
        uint16 costScore,
        uint16 speedScore,
        uint16 reliabilityScore,
        uint16 securityScore,
        bool speedPriority,
        bool multiHop
    ) public view {
        costScore = uint16(bound(costScore, 0, 10000));
        speedScore = uint16(bound(speedScore, 0, 10000));
        reliabilityScore = uint16(bound(reliabilityScore, 0, 10000));
        securityScore = uint16(bound(securityScore, 0, 10000));

        uint16 score = RouteOptimizer.calculateScore(
            defaultWeights,
            costScore,
            speedScore,
            reliabilityScore,
            securityScore,
            speedPriority,
            multiHop
        );

        assertTrue(score <= 10000);
    }

    function testFuzz_LiquidityImpact_QuadraticGrowth(
        uint256 amount,
        uint256 liquidity
    ) public pure {
        amount = bound(amount, 0.001 ether, 10000 ether);
        liquidity = bound(liquidity, 1 ether, 100000 ether);

        uint16 impact = RouteOptimizer.calculateLiquidityImpact(
            amount,
            liquidity
        );
        assertTrue(impact <= 10000);
    }

    function testFuzz_CombineProbabilities_NeverExceedsBPS(
        uint16 prob1,
        uint16 prob2
    ) public pure {
        prob1 = uint16(bound(prob1, 0, 10000));
        prob2 = uint16(bound(prob2, 0, 10000));

        uint16[] memory probs = new uint16[](2);
        probs[0] = prob1;
        probs[1] = prob2;

        uint16 combined = RouteOptimizer.combineProbabilities(probs);
        assertTrue(combined <= 10000);
    }

    function testFuzz_NormalizeInverse_AlwaysValid(
        uint256 value,
        uint256 minVal,
        uint256 maxVal
    ) public pure {
        minVal = bound(minVal, 0, 1e18);
        maxVal = bound(maxVal, minVal + 1, 1e18 + 1);
        value = bound(value, 0, 2e18);

        uint16 score = RouteOptimizer.normalizeInverse(value, minVal, maxVal);
        assertTrue(score <= 10000);
    }

    function testFuzz_NormalizeDirect_AlwaysValid(
        uint256 value,
        uint256 minVal,
        uint256 maxVal
    ) public pure {
        minVal = bound(minVal, 0, 1e18);
        maxVal = bound(maxVal, minVal + 1, 1e18 + 1);
        value = bound(value, 0, 2e18);

        uint16 score = RouteOptimizer.normalizeDirect(value, minVal, maxVal);
        assertTrue(score <= 10000);
    }
}
