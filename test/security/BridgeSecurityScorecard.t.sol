// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeSecurityScorecard} from "../../contracts/security/BridgeSecurityScorecard.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract BridgeSecurityScorecardTest is Test {
    BridgeSecurityScorecard public scorecard;
    address public admin;
    address public bridge1;
    address public bridge2;
    address public attacker;

    bytes32 public constant SCORE_ADMIN_ROLE = keccak256("SCORE_ADMIN_ROLE");

    function setUp() public {
        admin = makeAddr("admin");
        bridge1 = makeAddr("bridge1");
        bridge2 = makeAddr("bridge2");
        attacker = makeAddr("attacker");

        vm.prank(admin);
        scorecard = new BridgeSecurityScorecard(admin);
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_grantsAdminRole() public view {
        assertTrue(scorecard.hasRole(scorecard.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_constructor_grantsScoreAdminRole() public view {
        assertTrue(scorecard.hasRole(SCORE_ADMIN_ROLE, admin));
    }

    function test_constructor_setsDefaultMinimumSafeScore() public view {
        assertEq(scorecard.minimumSafeScore(), 70);
    }

    /*//////////////////////////////////////////////////////////////
                       UPDATE SCORE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_updateScore_setsAllComponents() public {
        vm.prank(admin);
        scorecard.updateScore(bridge1, 18, 15, 20, 19, 10);

        BridgeSecurityScorecard.SecurityScore memory score = scorecard.getScore(
            bridge1
        );
        assertEq(score.validatorDecentralization, 18);
        assertEq(score.economicSecurity, 15);
        assertEq(score.auditScore, 20);
        assertEq(score.uptimeScore, 19);
        assertEq(score.incidentHistory, 10);
        assertEq(score.totalScore, 82);
        assertEq(score.lastUpdated, block.timestamp);
    }

    function test_updateScore_emitsScoreUpdated() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit BridgeSecurityScorecard.ScoreUpdated(bridge1, 50);
        scorecard.updateScore(bridge1, 10, 10, 10, 10, 10);
    }

    function test_updateScore_revertsOnDecentralizationAbove20() public {
        vm.prank(admin);
        vm.expectRevert("Score component > 20");
        scorecard.updateScore(bridge1, 21, 10, 10, 10, 10);
    }

    function test_updateScore_revertsOnEconomicAbove20() public {
        vm.prank(admin);
        vm.expectRevert("Score component > 20");
        scorecard.updateScore(bridge1, 10, 21, 10, 10, 10);
    }

    function test_updateScore_revertsOnAuditAbove20() public {
        vm.prank(admin);
        vm.expectRevert("Score component > 20");
        scorecard.updateScore(bridge1, 10, 10, 21, 10, 10);
    }

    function test_updateScore_revertsOnUptimeAbove20() public {
        vm.prank(admin);
        vm.expectRevert("Score component > 20");
        scorecard.updateScore(bridge1, 10, 10, 10, 21, 10);
    }

    function test_updateScore_revertsOnHistoryAbove20() public {
        vm.prank(admin);
        vm.expectRevert("Score component > 20");
        scorecard.updateScore(bridge1, 10, 10, 10, 10, 21);
    }

    function test_updateScore_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        scorecard.updateScore(bridge1, 10, 10, 10, 10, 10);
    }

    function test_updateScore_overwritesPreviousScore() public {
        vm.startPrank(admin);
        scorecard.updateScore(bridge1, 20, 20, 20, 20, 20);
        assertEq(scorecard.getScore(bridge1).totalScore, 100);

        scorecard.updateScore(bridge1, 5, 5, 5, 5, 5);
        assertEq(scorecard.getScore(bridge1).totalScore, 25);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                      IS BRIDGE SAFE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_isBridgeSafe_returnsTrueWhenAboveThreshold() public {
        vm.prank(admin);
        scorecard.updateScore(bridge1, 15, 15, 15, 15, 15);
        // Total: 75, threshold: 70
        assertTrue(scorecard.isBridgeSafe(bridge1));
    }

    function test_isBridgeSafe_returnsTrueAtExactThreshold() public {
        vm.prank(admin);
        scorecard.updateScore(bridge1, 14, 14, 14, 14, 14);
        // Total: 70, threshold: 70
        assertTrue(scorecard.isBridgeSafe(bridge1));
    }

    function test_isBridgeSafe_returnsFalseWhenBelowThreshold() public {
        vm.prank(admin);
        scorecard.updateScore(bridge1, 10, 10, 10, 10, 10);
        // Total: 50, threshold: 70
        assertFalse(scorecard.isBridgeSafe(bridge1));
    }

    function test_isBridgeSafe_returnsFalseForUnscored() public view {
        // Unscored bridge has totalScore=0
        assertFalse(scorecard.isBridgeSafe(bridge2));
    }

    /*//////////////////////////////////////////////////////////////
                     SET MINIMUM SAFE SCORE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setMinimumSafeScore_updatesThreshold() public {
        vm.prank(admin);
        scorecard.setMinimumSafeScore(50);
        assertEq(scorecard.minimumSafeScore(), 50);
    }

    function test_setMinimumSafeScore_emitsEvent() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit BridgeSecurityScorecard.MinimumSafeScoreUpdated(50);
        scorecard.setMinimumSafeScore(50);
    }

    function test_setMinimumSafeScore_revertsAbove100() public {
        vm.prank(admin);
        vm.expectRevert("Invalid score");
        scorecard.setMinimumSafeScore(101);
    }

    function test_setMinimumSafeScore_allowsZero() public {
        vm.prank(admin);
        scorecard.setMinimumSafeScore(0);
        assertEq(scorecard.minimumSafeScore(), 0);
    }

    function test_setMinimumSafeScore_revertsForNonAdmin() public {
        vm.prank(attacker);
        vm.expectRevert();
        scorecard.setMinimumSafeScore(50);
    }

    /*//////////////////////////////////////////////////////////////
                      MULTIPLE BRIDGES TEST
    //////////////////////////////////////////////////////////////*/

    function test_multipleBridges_independentScores() public {
        vm.startPrank(admin);
        scorecard.updateScore(bridge1, 20, 20, 20, 20, 20);
        scorecard.updateScore(bridge2, 5, 5, 5, 5, 5);
        vm.stopPrank();

        assertTrue(scorecard.isBridgeSafe(bridge1));
        assertFalse(scorecard.isBridgeSafe(bridge2));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_updateScore_validComponents(
        uint256 d,
        uint256 e,
        uint256 a,
        uint256 u,
        uint256 h
    ) public {
        d = bound(d, 0, 20);
        e = bound(e, 0, 20);
        a = bound(a, 0, 20);
        u = bound(u, 0, 20);
        h = bound(h, 0, 20);

        vm.prank(admin);
        scorecard.updateScore(bridge1, d, e, a, u, h);

        BridgeSecurityScorecard.SecurityScore memory score = scorecard.getScore(
            bridge1
        );
        assertEq(score.totalScore, d + e + a + u + h);
    }

    function testFuzz_setMinimumSafeScore_validRange(uint256 newMin) public {
        newMin = bound(newMin, 0, 100);
        vm.prank(admin);
        scorecard.setMinimumSafeScore(newMin);
        assertEq(scorecard.minimumSafeScore(), newMin);
    }
}
