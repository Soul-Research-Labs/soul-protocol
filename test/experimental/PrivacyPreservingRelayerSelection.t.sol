// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyPreservingRelayerSelection} from "../../contracts/experimental/privacy/PrivacyPreservingRelayerSelection.sol";
import {ExperimentalFeatureRegistry} from "../../contracts/security/ExperimentalFeatureRegistry.sol";

/**
 * @title PrivacyPreservingRelayerSelectionTest
 * @notice Tests for the experimental VRF-based private relayer selection
 */
contract PrivacyPreservingRelayerSelectionTest is Test {
    PrivacyPreservingRelayerSelection public selection;
    ExperimentalFeatureRegistry public featureReg;

    address admin;
    address relayer1 = makeAddr("relayer1");
    address relayer2 = makeAddr("relayer2");
    address relayer3 = makeAddr("relayer3");
    address oracle = makeAddr("oracle");
    address requester = makeAddr("requester");

    bytes32 constant VRF_PUB_KEY = keccak256("vrfPubKey");
    bytes32 constant PUB_KEY_HASH_1 = keccak256("relayer1PubKey");
    bytes32 constant PUB_KEY_HASH_2 = keccak256("relayer2PubKey");
    bytes32 constant PUB_KEY_HASH_3 = keccak256("relayer3PubKey");

    function setUp() public {
        admin = address(this);

        // Deploy feature registry (features pre-registered as EXPERIMENTAL by constructor)
        featureReg = new ExperimentalFeatureRegistry(admin);

        // Deploy selection contract
        selection = new PrivacyPreservingRelayerSelection(
            VRF_PUB_KEY,
            address(featureReg)
        );

        // Grant oracle role
        selection.grantRole(selection.ORACLE_ROLE(), oracle);

        // Fund relayers
        vm.deal(relayer1, 10 ether);
        vm.deal(relayer2, 10 ether);
        vm.deal(relayer3, 10 ether);
    }

    // =========================================================================
    // DEPLOYMENT
    // =========================================================================

    function test_deployment() public view {
        assertEq(selection.vrfPublicKey(), VRF_PUB_KEY);
        assertEq(selection.getActiveRelayerCount(), 0);
        assertTrue(selection.hasRole(selection.DEFAULT_ADMIN_ROLE(), admin));
    }

    // =========================================================================
    // RELAYER REGISTRATION
    // =========================================================================

    function test_registerRelayer() public {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        assertEq(selection.getActiveRelayerCount(), 1);

        PrivacyPreservingRelayerSelection.Relayer memory r = selection
            .getRelayerInfo(relayer1);
        assertEq(r.relayerAddress, relayer1);
        assertEq(r.publicKeyHash, PUB_KEY_HASH_1);
        assertEq(r.stake, 1 ether);
        assertTrue(r.active);
    }

    function test_registerRelayer_insufficientStake_reverts() public {
        vm.prank(relayer1);
        vm.expectRevert();
        selection.registerRelayer{value: 0.5 ether}(PUB_KEY_HASH_1);
    }

    function test_registerMultipleRelayers() public {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        vm.prank(relayer2);
        selection.registerRelayer{value: 2 ether}(PUB_KEY_HASH_2);

        assertEq(selection.getActiveRelayerCount(), 2);
    }

    // =========================================================================
    // ADD STAKE
    // =========================================================================

    function test_addStake() public {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        vm.prank(relayer1);
        selection.addStake{value: 1 ether}();

        PrivacyPreservingRelayerSelection.Relayer memory r = selection
            .getRelayerInfo(relayer1);
        assertEq(r.stake, 2 ether);
    }

    // =========================================================================
    // DEACTIVATE
    // =========================================================================

    function test_deactivateRelayer() public {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        vm.prank(relayer1);
        selection.deactivateRelayer();

        PrivacyPreservingRelayerSelection.Relayer memory r = selection
            .getRelayerInfo(relayer1);
        assertFalse(r.active);
        assertEq(selection.getActiveRelayerCount(), 0);
    }

    // =========================================================================
    // SELECTION REQUEST
    // =========================================================================

    function test_requestSelection() public {
        _registerThreeRelayers();

        bytes32 commitHash = keccak256(abi.encodePacked("secret"));
        vm.prank(requester);
        bytes32 requestId = selection.requestSelection(commitHash, 2);
        assertTrue(requestId != bytes32(0));
    }

    function test_requestSelection_tooManyRelayers_reverts() public {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        bytes32 commitHash = keccak256(abi.encodePacked("secret"));
        vm.prank(requester);
        vm.expectRevert();
        selection.requestSelection(commitHash, 5); // Only 1 active relayer
    }

    // =========================================================================
    // SELECTION REVEAL
    // =========================================================================

    function test_revealSelection() public {
        _registerThreeRelayers();

        bytes32 randomness = keccak256("randomness");

        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        prefs.minReputation = 0;
        prefs.maxLatency = type(uint256).max;
        prefs.excludedRelayers = new bytes32[](0);
        prefs.feeBudget = 0;

        // Compute commitment as contract expects: H(sender, randomness, prefs...)
        bytes32 commitHash = keccak256(
            abi.encodePacked(
                requester,
                randomness,
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );

        vm.prank(requester);
        bytes32 requestId = selection.requestSelection(commitHash, 2);

        vm.prank(requester);
        selection.revealSelection(requestId, randomness, prefs);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_getActiveRelayers() public {
        _registerThreeRelayers();

        address[] memory relayers = selection.getActiveRelayers();
        assertEq(relayers.length, 3);
    }

    function test_getStats() public {
        _registerThreeRelayers();

        (
            uint256 relayerCount,
            uint256 totalStakeAmount,
            uint256 requests
        ) = selection.getStats();
        assertEq(relayerCount, 3);
        assertEq(totalStakeAmount, 3 ether);
        assertEq(requests, 0);
    }

    function test_isSelectionValid_noRequest() public view {
        assertFalse(selection.isSelectionValid(keccak256("nonexistent")));
    }

    // =========================================================================
    // ORACLE ROLE
    // =========================================================================

    function test_reportRelayCompletion() public {
        _registerThreeRelayers();

        bytes32 requestId = keccak256("someRequest");

        vm.prank(oracle);
        selection.reportRelayCompletion(relayer1, requestId, true);

        PrivacyPreservingRelayerSelection.Relayer memory r = selection
            .getRelayerInfo(relayer1);
        assertEq(r.successfulRelays, 1);
    }

    function test_reportRelayCompletion_failure() public {
        _registerThreeRelayers();

        bytes32 requestId = keccak256("someRequest");

        vm.prank(oracle);
        selection.reportRelayCompletion(relayer1, requestId, false);

        PrivacyPreservingRelayerSelection.Relayer memory r = selection
            .getRelayerInfo(relayer1);
        assertEq(r.failedRelays, 1);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _registerThreeRelayers() internal {
        vm.prank(relayer1);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_1);

        vm.prank(relayer2);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_2);

        vm.prank(relayer3);
        selection.registerRelayer{value: 1 ether}(PUB_KEY_HASH_3);
    }
}
