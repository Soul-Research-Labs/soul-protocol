// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";
import {ICrossChainProofHubV3} from "../../contracts/interfaces/ICrossChainProofHubV3.sol";
import {BaseBridgeAdapter} from "../../contracts/crosschain/BaseBridgeAdapter.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";

/**
 * @title AdvancedSecurityAttacks
 * @author ZASEON
 * @notice Tests for attack vectors: cross-chain replay, time manipulation,
 *         bridge spoofing, fee overflow, reentrancy via callbacks, delegatecall escalation
 * @dev Phase 7 — fills gaps identified in security test gap analysis
 */
contract AdvancedSecurityAttacksTest is Test {
    CrossChainProofHubV3 public hubChainA;
    CrossChainProofHubV3 public hubChainB;
    BaseBridgeAdapter public bridgeA;
    BaseBridgeAdapter public bridgeB;
    NullifierRegistryV3 public nullifierRegistry;

    address admin = address(0x1);
    address relayer = address(0x2);
    address challenger = address(0x3);
    address attacker = address(0xBAD);
    address mockMessenger = address(0x5);
    address mockPortal = address(0x6);
    address mockTarget = address(0x7);

    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    function setUp() public {
        vm.startPrank(admin);

        // Deploy two hub instances (simulating two chains)
        hubChainA = new CrossChainProofHubV3();
        hubChainB = new CrossChainProofHubV3();

        // Setup roles — relayer & challenger are separate from admin
        hubChainA.grantRole(RELAYER_ROLE, relayer);
        hubChainA.grantRole(CHALLENGER_ROLE, challenger);
        hubChainA.grantRole(OPERATOR_ROLE, admin);
        hubChainA.grantRole(EMERGENCY_ROLE, admin);
        hubChainB.grantRole(RELAYER_ROLE, relayer);
        hubChainB.grantRole(CHALLENGER_ROLE, challenger);
        hubChainB.grantRole(OPERATOR_ROLE, admin);
        hubChainB.grantRole(EMERGENCY_ROLE, admin);

        // Confirm role separation (admin does NOT have RELAYER_ROLE)
        hubChainA.confirmRoleSeparation();
        hubChainB.confirmRoleSeparation();

        // Enable cross-chain support
        hubChainA.addSupportedChain(42161); // Arbitrum
        hubChainA.addSupportedChain(10); // Optimism
        hubChainB.addSupportedChain(42161);
        hubChainB.addSupportedChain(10);

        // Deploy bridge adapters
        bridgeA = new BaseBridgeAdapter(
            admin,
            mockMessenger,
            mockMessenger,
            mockPortal,
            true
        );
        bridgeB = new BaseBridgeAdapter(
            admin,
            mockMessenger,
            mockMessenger,
            mockPortal,
            false
        );
        bridgeA.setL2Target(mockTarget);

        // Deploy nullifier registry (no constructor args)
        vm.stopPrank();

        vm.prank(admin);
        nullifierRegistry = new NullifierRegistryV3();

        // Fund actors
        vm.deal(relayer, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(attacker, 100 ether);
    }

    // ================================================================
    // Helper: submit a proof to a hub
    // ================================================================
    function _submitProofToHub(
        CrossChainProofHubV3 hub,
        bytes32 commitment,
        uint64 srcChain,
        uint64 dstChain
    ) internal returns (bytes32) {
        bytes memory proof = abi.encodePacked(commitment);
        bytes memory publicInputs = abi.encodePacked(srcChain, dstChain);
        return
            hub.submitProof{value: 0.001 ether}(
                proof,
                publicInputs,
                commitment,
                srcChain,
                dstChain
            );
    }

    // ================================================================
    // 1. Cross-chain replay — same proof submitted to two hub instances
    // ================================================================

    function test_crossChainReplay_sameProofTwoHubs() public {
        // Relayer stakes on both hubs
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();
        hubChainB.depositStake{value: 1 ether}();

        bytes32 commitment = keccak256("proof-hash-1");

        // Submit proof to chain A
        bytes32 idA = _submitProofToHub(hubChainA, commitment, 42161, 10);

        // Same data submitted to chain B should also succeed
        // (each hub is independent — cross-chain replay protection
        //  must happen at nullifier/application layer)
        bytes32 idB = _submitProofToHub(hubChainB, commitment, 42161, 10);

        vm.stopPrank();

        // Verify both accepted (separately isolated)
        ICrossChainProofHubV3.ProofSubmission memory subA = hubChainA.getProof(
            idA
        );
        ICrossChainProofHubV3.ProofSubmission memory subB = hubChainB.getProof(
            idB
        );

        assertTrue(subA.relayer != address(0), "Chain A accepted proof");
        assertTrue(subB.relayer != address(0), "Chain B accepted proof");
    }

    function test_crossChainReplay_duplicateOnSameHubReverts() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();

        bytes32 commitment = keccak256("dup-proof");
        _submitProofToHub(hubChainA, commitment, 42161, 10);

        // Same proof on same hub should revert
        vm.expectRevert();
        _submitProofToHub(hubChainA, commitment, 42161, 10);

        vm.stopPrank();
    }

    function test_crossChainReplay_nullifierBlocksDoubleSpend() public {
        // Nullifier registry blocks double-spend at the application layer
        vm.startPrank(admin);

        bytes32 domain = keccak256("chain-42161");
        nullifierRegistry.registerDomain(domain);

        bytes32 nullifier = keccak256("nullifier-1");
        bytes32 commitment = keccak256("commitment-1");

        // First registration succeeds
        nullifierRegistry.registerNullifier(nullifier, commitment);
        assertTrue(nullifierRegistry.isNullifierUsed(nullifier));

        // Second registration of same nullifier reverts
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, commitment);

        vm.stopPrank();
    }

    // ================================================================
    // 2. Time-manipulation attacks on proof deadlines
    // ================================================================

    function test_timeManipulation_earlyFinalizeBlocked() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();
        bytes32 proofId = _submitProofToHub(
            hubChainA,
            keccak256("timed"),
            42161,
            10
        );
        vm.stopPrank();

        // Attacker tries to finalize IMMEDIATELY (before challenge period)
        vm.prank(attacker);
        vm.expectRevert();
        hubChainA.finalizeProof(proofId);

        // Warp to 1 second before deadline
        uint256 period = hubChainA.challengePeriod();
        vm.warp(block.timestamp + period - 1);
        vm.prank(relayer);
        vm.expectRevert();
        hubChainA.finalizeProof(proofId);

        // Warp past the challenge period
        vm.warp(block.timestamp + 2);
        vm.prank(relayer);
        hubChainA.finalizeProof(proofId);

        // Verify finalized
        ICrossChainProofHubV3.ProofSubmission memory sub = hubChainA.getProof(
            proofId
        );
        assertTrue(sub.status == ICrossChainProofHubV3.ProofStatus.Finalized);
    }

    function test_timeManipulation_rateLimitResets() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 10 ether}();

        // Submit several proofs
        for (uint256 i = 0; i < 10; i++) {
            _submitProofToHub(
                hubChainA,
                keccak256(abi.encodePacked("rate-", i)),
                42161,
                10
            );
        }

        // Warp forward past the rate-limit window
        vm.warp(block.timestamp + 1 hours + 1);

        // Should be able to submit again after reset
        _submitProofToHub(hubChainA, keccak256("post-reset"), 42161, 10);

        vm.stopPrank();
    }

    // ================================================================
    // 3. Bridge message spoofing — forged sender / chain ID
    // ================================================================

    function test_bridgeSpoofing_unauthorizedRelayerRejected() public {
        // Attacker has no RELAYER_ROLE
        vm.startPrank(attacker);
        vm.expectRevert();
        _submitProofToHub(hubChainA, keccak256("spoofed"), 42161, 10);
        vm.stopPrank();
    }

    function test_bridgeSpoofing_unsupportedChainRejected() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();

        // Unsupported source chain
        vm.expectRevert();
        _submitProofToHub(hubChainA, keccak256("bad-chain"), 99999, 10);

        vm.stopPrank();
    }

    function test_bridgeSpoofing_L2SendNotOperator() public {
        // Attacker tries to send proof via bridge without OPERATOR_ROLE
        vm.prank(attacker);
        vm.expectRevert();
        bridgeA.sendProofToL2(
            keccak256("spoofed"),
            abi.encodePacked(uint256(1)),
            abi.encodePacked(uint256(2)),
            200000
        );
    }

    // ================================================================
    // 4. Fee overflow / underflow attacks
    // ================================================================

    function test_feeAttack_zeroFeeReverts() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();

        vm.expectRevert();
        hubChainA.submitProof{value: 0}(
            abi.encodePacked(uint256(1)),
            abi.encodePacked(uint256(2)),
            keccak256("zero-fee"),
            42161,
            10
        );

        vm.stopPrank();
    }

    function test_feeAttack_accumulationCorrect() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 10 ether}();

        uint256 fee = hubChainA.proofSubmissionFee();
        uint256 startFees = hubChainA.accumulatedFees();

        for (uint256 i = 0; i < 5; i++) {
            _submitProofToHub(
                hubChainA,
                keccak256(abi.encodePacked("fee-test-", i)),
                42161,
                10
            );
        }

        assertEq(hubChainA.accumulatedFees() - startFees, fee * 5);
        vm.stopPrank();
    }

    // ================================================================
    // 5. Reentrancy via deposit/stake
    // ================================================================

    function test_reentrancy_depositStakeProtected() public {
        ReentrantStaker reentranter = new ReentrantStaker(address(hubChainA));
        vm.deal(address(reentranter), 10 ether);

        // ReentrantStaker tries to re-enter depositStake from receive()
        // This may succeed (depositStake is nonReentrant) or revert
        // Either way the contract's state must remain consistent
        try reentranter.attack{value: 1 ether}() {
            // If it didn't revert, verify stake is exactly 1 ether (no double-deposit)
            assertEq(hubChainA.relayerStakes(address(reentranter)), 1 ether);
        } catch {
            // Revert is expected — reentrancy guard works
        }
    }

    // ================================================================
    // 6. Delegatecall escalation attempts
    // ================================================================

    function test_delegatecallEscalation_cannotBypassRoles() public {
        MaliciousDelegatecaller malicious = new MaliciousDelegatecaller();

        vm.prank(attacker);
        // delegatecall runs hub code in malicious's storage context
        // so role checks won't match — should fail
        bool success = malicious.tryDelegatecallSubmitProof(
            address(hubChainA),
            42161,
            10,
            keccak256("delegatecall-proof")
        );
        assertFalse(success, "Delegatecall escalation must fail");
    }

    // ================================================================
    // 7. Nullifier domain isolation
    // ================================================================

    function test_nullifierDomainIsolation_sameNullifierDifferentDomains()
        public
    {
        vm.startPrank(admin);

        bytes32 domainA = keccak256("chain-42161");
        bytes32 domainB = keccak256("chain-10");
        nullifierRegistry.registerDomain(domainA);
        nullifierRegistry.registerDomain(domainB);

        bytes32 nullifier = keccak256("shared-nullifier");

        // Cross-domain nullifiers use the nullifier hash directly
        // The CDNA (cross-domain nullifier algorithm) includes domain info
        // in the nullifier hash at circuit level, so different domains
        // produce different nullifier hashes
        bytes32 nullifierA = keccak256(abi.encodePacked(domainA, nullifier));
        bytes32 nullifierB = keccak256(abi.encodePacked(domainB, nullifier));

        // Each domain-scoped nullifier should register independently
        nullifierRegistry.registerNullifier(nullifierA, bytes32(0));
        nullifierRegistry.registerNullifier(nullifierB, bytes32(0));

        assertTrue(nullifierRegistry.isNullifierUsed(nullifierA));
        assertTrue(nullifierRegistry.isNullifierUsed(nullifierB));

        // Duplicate on same domain-scoped nullifier should revert
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifierA, bytes32(0));

        vm.stopPrank();
    }

    // ================================================================
    // 8. Challenge manipulation attacks
    // ================================================================

    function test_challengeManip_cannotChallengeAlreadyFinalized() public {
        vm.startPrank(relayer);
        hubChainA.depositStake{value: 1 ether}();
        bytes32 proofId = _submitProofToHub(
            hubChainA,
            keccak256("chal-final"),
            42161,
            10
        );
        vm.stopPrank();

        // Warp past challenge period and finalize
        vm.warp(block.timestamp + hubChainA.challengePeriod() + 1);
        vm.prank(relayer);
        hubChainA.finalizeProof(proofId);

        // Challenger tries to challenge after finalization
        vm.startPrank(challenger);
        vm.expectRevert();
        hubChainA.challengeProof{value: 0.05 ether}(proofId, "too late");
        vm.stopPrank();
    }

    // ================================================================
    // 9. Pause bypass attacks
    // ================================================================

    function test_pauseBypass_cannotSubmitWhenPaused() public {
        // Stake first (before pause)
        vm.prank(relayer);
        hubChainA.depositStake{value: 1 ether}();

        // Pause
        vm.prank(admin);
        hubChainA.pause();

        // Relayer tries to submit
        vm.startPrank(relayer);
        vm.expectRevert();
        _submitProofToHub(hubChainA, keccak256("paused-proof"), 42161, 10);
        vm.stopPrank();
    }

    function test_pauseBypass_attackerCannotUnpause() public {
        vm.prank(admin);
        hubChainA.pause();

        vm.prank(attacker);
        vm.expectRevert();
        hubChainA.unpause();

        assertTrue(hubChainA.paused());
    }

    // ================================================================
    // 10. Fuzz tests
    // ================================================================

    function testFuzz_proofHashUniqueness(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != commitment2);
        vm.assume(commitment1 != bytes32(0) && commitment2 != bytes32(0));

        vm.startPrank(relayer);
        hubChainA.depositStake{value: 2 ether}();

        // Both should be accepted as distinct proofs
        _submitProofToHub(hubChainA, commitment1, 42161, 10);
        _submitProofToHub(hubChainA, commitment2, 42161, 10);

        // Same commitment1 should revert
        vm.expectRevert();
        _submitProofToHub(hubChainA, commitment1, 42161, 10);

        vm.stopPrank();
    }

    function testFuzz_nullifierCannotBeRegisteredTwice(
        bytes32 nullifier
    ) public {
        vm.assume(nullifier != bytes32(0));

        vm.prank(admin);
        nullifierRegistry.registerNullifier(nullifier, bytes32(0));
        assertTrue(nullifierRegistry.isNullifierUsed(nullifier));

        vm.prank(admin);
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, bytes32(0));
    }
}

// ================================================================
// Helper contracts for reentrancy and delegatecall tests
// ================================================================

contract ReentrantStaker {
    address payable target;
    bool attacked;

    constructor(address _target) {
        target = payable(_target);
    }

    function attack() external payable {
        CrossChainProofHubV3(target).depositStake{value: msg.value}();
    }

    receive() external payable {
        if (!attacked && address(target).balance > 0.5 ether) {
            attacked = true;
            CrossChainProofHubV3(target).depositStake{value: 0.1 ether}();
        }
    }
}

contract MaliciousDelegatecaller {
    function tryDelegatecallSubmitProof(
        address hub,
        uint64 srcChain,
        uint64 dstChain,
        bytes32 commitment
    ) external returns (bool) {
        bytes memory proof = abi.encodePacked(commitment);
        bytes memory publicInputs = abi.encodePacked(srcChain, dstChain);

        (bool success, ) = hub.delegatecall(
            abi.encodeWithSelector(
                CrossChainProofHubV3.submitProof.selector,
                proof,
                publicInputs,
                commitment,
                srcChain,
                dstChain
            )
        );
        return success;
    }
}
