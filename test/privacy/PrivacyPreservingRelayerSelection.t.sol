// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/privacy/PrivacyPreservingRelayerSelection.sol";

contract PrivacyPreservingRelayerSelectionTest is Test {
    PrivacyPreservingRelayerSelection public selector;
    bytes32 public constant VRF_PUB_KEY = keccak256("vrf_pub_key");

    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");
    address public relayer3 = makeAddr("relayer3");
    address public oracle = makeAddr("oracle");

    function setUp() public {
        selector = new PrivacyPreservingRelayerSelection(VRF_PUB_KEY);

        // Grant oracle role
        selector.grantRole(selector.ORACLE_ROLE(), oracle);

        // Fund relayers
        vm.deal(relayer1, 10 ether);
        vm.deal(relayer2, 10 ether);
        vm.deal(relayer3, 10 ether);
    }

    // ─── Registration ───────────────────────────────────────

    function test_registerRelayer() public {
        vm.prank(relayer1);
        selector.registerRelayer{value: 1 ether}(keccak256("pk1"));

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertEq(r.relayerAddress, relayer1);
        assertEq(r.stake, 1 ether);
        assertTrue(r.active);
        assertEq(r.reputation, 5000); // Default reputation
    }

    function test_registerRelayer_revert_insufficientStake() public {
        vm.prank(relayer1);
        vm.expectRevert(
            PrivacyPreservingRelayerSelection.InsufficientStake.selector
        );
        selector.registerRelayer{value: 0.5 ether}(keccak256("pk1"));
    }

    function test_registerRelayer_emitsEvent() public {
        vm.prank(relayer1);
        vm.expectEmit(true, false, false, true);
        emit PrivacyPreservingRelayerSelection.RelayerRegistered(
            relayer1,
            1 ether,
            keccak256("pk1")
        );
        selector.registerRelayer{value: 1 ether}(keccak256("pk1"));
    }

    // ─── Add Stake ──────────────────────────────────────────

    function test_addStake() public {
        _registerRelayer(relayer1, 1 ether);

        vm.prank(relayer1);
        selector.addStake{value: 2 ether}();

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertEq(r.stake, 3 ether);
    }

    function test_addStake_revert_notRelayer() public {
        vm.prank(relayer2);
        vm.expectRevert();
        selector.addStake{value: 1 ether}();
    }

    // ─── Deactivation ───────────────────────────────────────

    function test_deactivateRelayer() public {
        _registerRelayer(relayer1, 2 ether);

        uint256 balBefore = relayer1.balance;

        vm.prank(relayer1);
        selector.deactivateRelayer();

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertFalse(r.active);
        assertEq(r.stake, 0);
        assertGe(relayer1.balance, balBefore + 2 ether - 1); // Allow rounding
    }

    function test_deactivateRelayer_emitsEvent() public {
        _registerRelayer(relayer1, 1 ether);

        vm.prank(relayer1);
        vm.expectEmit(true, false, false, true);
        emit PrivacyPreservingRelayerSelection.RelayerDeactivated(
            relayer1,
            1 ether
        );
        selector.deactivateRelayer();
    }

    // ─── Selection Flow ─────────────────────────────────────

    function test_requestSelection() public {
        _registerRelayer(relayer1, 1 ether);

        bytes32 commitmentHash = keccak256("commitment");
        bytes32 requestId = selector.requestSelection(commitmentHash, 1);
        assertTrue(requestId != bytes32(0));
        assertEq(selector.requestCount(), 1);
    }

    function test_requestSelection_revert_tooManyRelayers() public {
        _registerRelayer(relayer1, 1 ether);

        vm.expectRevert(
            PrivacyPreservingRelayerSelection.TooManyRelayers.selector
        );
        selector.requestSelection(keccak256("c"), 5); // Only 1 active
    }

    function test_requestSelection_revert_noActiveRelayers() public {
        vm.expectRevert(
            PrivacyPreservingRelayerSelection.NoActiveRelayers.selector
        );
        selector.requestSelection(keccak256("c"), 1);
    }

    function test_revealSelection() public {
        _registerRelayer(relayer1, 1 ether);

        bytes32 randomness = keccak256("random");
        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        prefs.minReputation = 0;
        prefs.maxLatency = 1000;
        prefs.feeBudget = 1 ether;

        // Commitment = H(sender, randomness, prefs.minRep, prefs.maxLatency, H(excludedRelayers), prefs.feeBudget)
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                address(this),
                randomness,
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );
        bytes32 requestId = selector.requestSelection(commitmentHash, 1);

        selector.revealSelection(requestId, randomness, prefs);
    }

    function test_revealSelection_revert_invalidCommitment() public {
        _registerRelayer(relayer1, 1 ether);

        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                address(this),
                keccak256("real"),
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );
        bytes32 requestId = selector.requestSelection(commitmentHash, 1);

        vm.expectRevert(
            PrivacyPreservingRelayerSelection.InvalidCommitment.selector
        );
        selector.revealSelection(requestId, keccak256("wrong_random"), prefs);
    }

    function test_revealSelection_revert_alreadyRevealed() public {
        _registerRelayer(relayer1, 1 ether);

        bytes32 randomness = keccak256("random");
        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                address(this),
                randomness,
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );
        bytes32 requestId = selector.requestSelection(commitmentHash, 1);

        selector.revealSelection(requestId, randomness, prefs);

        vm.expectRevert(
            PrivacyPreservingRelayerSelection.AlreadyRevealed.selector
        );
        selector.revealSelection(requestId, randomness, prefs);
    }

    // ─── Oracle Functions ───────────────────────────────────

    function test_fulfillSelection() public {
        _registerThreeRelayers();

        bytes32 randomness = keccak256("random");
        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                address(this),
                randomness,
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );
        bytes32 requestId = selector.requestSelection(commitmentHash, 2);

        selector.revealSelection(requestId, randomness, prefs);

        // The seed stored is keccak256(randomness, blockhash(requestBlock))
        // In forge tests, blockhash(block.number) = bytes32(0) since we're in the same block
        bytes32 vrfSeed = keccak256(abi.encodePacked(randomness, bytes32(0)));

        PrivacyPreservingRelayerSelection.VRFProof memory proof;
        proof.c = keccak256("c");
        proof.s = keccak256("s");
        // gamma = keccak256(vrfPublicKey, seed, c, s)
        proof.gamma = keccak256(
            abi.encodePacked(VRF_PUB_KEY, vrfSeed, proof.c, proof.s)
        );

        vm.prank(oracle);
        selector.fulfillSelection(requestId, proof);

        address[] memory selected = selector.getSelectedRelayers(requestId);
        assertEq(selected.length, 2);
    }

    function test_fulfillSelection_revert_notOracle() public {
        _registerRelayer(relayer1, 1 ether);

        bytes32 randomness = keccak256("r");
        PrivacyPreservingRelayerSelection.SelectionPreferences memory prefs;
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                address(this),
                randomness,
                prefs.minReputation,
                prefs.maxLatency,
                keccak256(abi.encodePacked(prefs.excludedRelayers)),
                prefs.feeBudget
            )
        );
        bytes32 requestId = selector.requestSelection(commitmentHash, 1);

        selector.revealSelection(requestId, randomness, prefs);

        PrivacyPreservingRelayerSelection.VRFProof memory proof;
        vm.prank(relayer1);
        vm.expectRevert();
        selector.fulfillSelection(requestId, proof);
    }

    function test_reportRelayCompletion_success() public {
        _registerRelayer(relayer1, 1 ether);

        bytes32 requestId = keccak256("req1");
        vm.prank(oracle);
        selector.reportRelayCompletion(relayer1, requestId, true);

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertEq(r.successfulRelays, 1);
    }

    function test_reportRelayCompletion_failure() public {
        _registerRelayer(relayer1, 1 ether);

        vm.prank(oracle);
        selector.reportRelayCompletion(relayer1, keccak256("req1"), false);

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertEq(r.failedRelays, 1);
    }

    function test_reportRelayCompletion_revert_notOracle() public {
        _registerRelayer(relayer1, 1 ether);

        vm.prank(relayer1);
        vm.expectRevert();
        selector.reportRelayCompletion(relayer1, keccak256("req"), true);
    }

    // ─── View Functions ─────────────────────────────────────

    function test_getActiveRelayerCount() public {
        assertEq(selector.getActiveRelayerCount(), 0);
        _registerRelayer(relayer1, 1 ether);
        assertEq(selector.getActiveRelayerCount(), 1);
        _registerRelayer(relayer2, 1 ether);
        assertEq(selector.getActiveRelayerCount(), 2);
    }

    function test_getActiveRelayers() public {
        _registerRelayer(relayer1, 1 ether);
        _registerRelayer(relayer2, 1 ether);

        address[] memory active = selector.getActiveRelayers();
        assertEq(active.length, 2);
    }

    function test_getStats() public {
        _registerRelayer(relayer1, 2 ether);
        _registerRelayer(relayer2, 3 ether);

        (uint256 count, uint256 stake, uint256 requests) = selector.getStats();
        assertEq(count, 2);
        assertEq(stake, 5 ether);
        assertEq(requests, 0);
    }

    function test_isSelectionValid_nonexistent() public view {
        assertFalse(selector.isSelectionValid(keccak256("nonexistent")));
    }

    // ─── Fuzz ───────────────────────────────────────────────

    function testFuzz_registerRelayer_stakeAboveMin(
        uint256 stakeAmount
    ) public {
        stakeAmount = bound(stakeAmount, 1 ether, 50 ether);
        vm.deal(relayer1, stakeAmount);
        vm.prank(relayer1);
        selector.registerRelayer{value: stakeAmount}(keccak256("pk"));

        PrivacyPreservingRelayerSelection.Relayer memory r = selector
            .getRelayerInfo(relayer1);
        assertEq(r.stake, stakeAmount);
    }

    // ─── Helpers ────────────────────────────────────────────

    function _registerRelayer(address relayer, uint256 stake) internal {
        vm.prank(relayer);
        selector.registerRelayer{value: stake}(
            keccak256(abi.encodePacked(relayer))
        );
    }

    function _registerThreeRelayers() internal {
        _registerRelayer(relayer1, 1 ether);
        _registerRelayer(relayer2, 1 ether);
        _registerRelayer(relayer3, 1 ether);
    }
}
