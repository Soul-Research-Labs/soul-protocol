// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKBoundStateLocks} from "../../contracts/primitives/ZKBoundStateLocks.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title CryptographicAttacks
 * @author Soul Protocol
 * @notice Comprehensive cryptographic attack vector testing
 * @dev Tests nullifier collision, proof forgery, replay, range proof soundness,
 *      and state commitment manipulation attacks per
 *      CROSS_CHAIN_PRIVACY_SECURITY_NEXT_STEPS.md Security Phase 3
 */
contract CryptographicAttacksTest is Test {
    // =========================================================================
    // CONTRACTS
    // =========================================================================

    ZKBoundStateLocks public stateLocks;
    NullifierRegistryV3 public nullifierRegistry;
    MockProofVerifier public mockVerifier;

    // =========================================================================
    // ACTORS
    // =========================================================================

    address public admin;
    address public attacker;
    address public victim;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 constant LOCK_ADMIN_ROLE = keccak256("LOCK_ADMIN_ROLE");
    bytes32 constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 constant DOMAIN_ADMIN_ROLE = keccak256("DOMAIN_ADMIN_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    bytes32 constant MOCK_VK_HASH = keccak256("MOCK_VK_HASH");
    bytes32 testDomain;

    // BN254 curve order
    uint256 constant FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        admin = address(this);
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");

        // Deploy mock verifier and contracts
        mockVerifier = new MockProofVerifier();
        stateLocks = new ZKBoundStateLocks(address(mockVerifier));
        nullifierRegistry = new NullifierRegistryV3();

        // Setup roles
        nullifierRegistry.grantRole(REGISTRAR_ROLE, admin);

        // Register verifier and domain for state locks
        stateLocks.registerVerifier(MOCK_VK_HASH, address(mockVerifier));
        testDomain = stateLocks.registerDomain(
            uint64(block.chainid),
            1,
            0,
            "TestDomain"
        );
    }

    // =========================================================================
    // 1. NULLIFIER COLLISION / DOUBLE-SPEND ATTACKS
    // =========================================================================

    /// @notice Test that the same nullifier cannot be registered twice (double-spend prevention)
    function test_attack_nullifierDoubleSpend() public {
        bytes32 nullifier = keccak256("spent_note_1");
        bytes32 commitment = keccak256("commitment_1");

        nullifierRegistry.registerNullifier(nullifier, commitment);
        assertTrue(nullifierRegistry.exists(nullifier));

        // Attempting to register the same nullifier again must revert
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, commitment);
    }

    /// @notice Fuzz: no two different commitments can share a nullifier
    function testFuzz_attack_nullifierUniqueness(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != commitment2);
        vm.assume(commitment1 != bytes32(0) && commitment2 != bytes32(0));

        bytes32 nullifier = keccak256(
            abi.encodePacked(commitment1, "nullifier_derive")
        );

        nullifierRegistry.registerNullifier(nullifier, commitment1);

        // Same nullifier with different commitment must fail
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, commitment2);
    }

    /// @notice Test batch nullifier registration rejects duplicates within a batch
    function test_attack_nullifierBatchDuplicate() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);

        nullifiers[0] = keccak256("batch_null_1");
        nullifiers[1] = keccak256("batch_null_2");
        nullifiers[2] = keccak256("batch_null_1"); // duplicate!

        commitments[0] = keccak256("batch_commit_1");
        commitments[1] = keccak256("batch_commit_2");
        commitments[2] = keccak256("batch_commit_3");

        // Batch with duplicate nullifier should revert
        vm.expectRevert();
        nullifierRegistry.batchRegisterNullifiers(nullifiers, commitments);
    }

    /// @notice Test that nullifier existence is consistent across single and batch checks
    function test_attack_nullifierExistenceConsistency() public {
        bytes32 nullifier = keccak256("consistency_test");
        bytes32 commitment = keccak256("consistency_commit");

        assertFalse(nullifierRegistry.exists(nullifier));

        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = nullifier;
        bool[] memory results = nullifierRegistry.batchExists(nullifiers);
        assertFalse(results[0]);

        // Register
        nullifierRegistry.registerNullifier(nullifier, commitment);

        // Both checks must now return true
        assertTrue(nullifierRegistry.exists(nullifier));
        results = nullifierRegistry.batchExists(nullifiers);
        assertTrue(results[0]);
    }

    // =========================================================================
    // 2. ZK PROOF FORGERY / INVALID PROOF ATTACKS
    // =========================================================================

    /// @notice Test that invalid ZK proof is rejected when verifier returns false
    function test_attack_proofForgery_invalidProofRejected() public {
        // Create a lock
        bytes32 lockId = stateLocks.createLock(
            keccak256("old_state"),
            keccak256("predicate"),
            keccak256("policy"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        // Set verifier to reject proofs
        mockVerifier.setVerificationResult(false);

        // Construct forged proof
        ZKBoundStateLocks.UnlockProof memory forgedProof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(42))), // garbage proof
                newStateCommitment: keccak256("fake_state"),
                nullifier: keccak256("fake_nullifier"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // Forged proof must be rejected
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InvalidProof.selector,
                lockId
            )
        );
        stateLocks.unlock(forgedProof);
    }

    /// @notice Test that valid proof with wrong lock ID fails
    function test_attack_proofForgery_wrongLockId() public {
        bytes32 lockId = stateLocks.createLock(
            keccak256("state_A"),
            keccak256("predicate_A"),
            keccak256("policy_A"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        bytes32 fakeLockId = keccak256("nonexistent_lock");

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: fakeLockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state"),
                nullifier: keccak256("null_1"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // Contract stores lockId=bytes32(0) for non-existent locks
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockDoesNotExist.selector,
                bytes32(0)
            )
        );
        stateLocks.unlock(proof);
    }

    /// @notice Test that unregistered verifier key falls through to general verifier
    /// and proof is rejected when general verifier rejects
    function test_attack_proofForgery_unregisteredVerifier() public {
        // General verifier rejects by default
        mockVerifier.setVerificationResult(false);

        bytes32 lockId = stateLocks.createLock(
            keccak256("state_B"),
            keccak256("predicate_B"),
            keccak256("policy_B"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        bytes32 fakeVkHash = keccak256("FAKE_VK");

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state"),
                nullifier: keccak256("null_2"),
                verifierKeyHash: fakeVkHash,
                auxiliaryData: ""
            });

        // Unregistered VK hash falls through to general proofVerifier,
        // which rejects the proof
        vm.expectRevert();
        stateLocks.unlock(proof);
    }

    // =========================================================================
    // 3. REPLAY / NULLIFIER REUSE ATTACKS
    // =========================================================================

    /// @notice Test that replaying a valid proof with the same nullifier fails
    function test_attack_proofReplay_nullifierReuse() public {
        mockVerifier.setVerificationResult(true);

        bytes32 lockId = stateLocks.createLock(
            keccak256("state_C"),
            keccak256("predicate_C"),
            keccak256("policy_C"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        bytes32 nullifier = keccak256("unique_nullifier_1");

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state_C"),
                nullifier: nullifier,
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // First unlock should succeed
        stateLocks.unlock(proof);

        // Create a new lock to try to reuse the nullifier
        bytes32 lockId2 = stateLocks.createLock(
            keccak256("state_D"),
            keccak256("predicate_D"),
            keccak256("policy_D"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        ZKBoundStateLocks.UnlockProof memory replayProof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId2,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("replay_state"),
                nullifier: nullifier, // REUSED nullifier
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // Replay must fail: nullifier already used
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        stateLocks.unlock(replayProof);
    }

    /// @notice Fuzz: no nullifier can be used twice across any lock
    function testFuzz_attack_nullifierReplayAcrossLocks(
        bytes32 stateA,
        bytes32 stateB,
        bytes32 nullifier
    ) public {
        vm.assume(stateA != bytes32(0) && stateB != bytes32(0));
        vm.assume(nullifier != bytes32(0));
        vm.assume(stateA != stateB);

        mockVerifier.setVerificationResult(true);

        bytes32 lockId1 = stateLocks.createLock(
            stateA,
            keccak256("pred1"),
            keccak256("pol1"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        ZKBoundStateLocks.UnlockProof memory proof1 = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId1,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256(abi.encode(stateA, "new")),
                nullifier: nullifier,
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        stateLocks.unlock(proof1);

        bytes32 lockId2 = stateLocks.createLock(
            stateB,
            keccak256("pred2"),
            keccak256("pol2"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        ZKBoundStateLocks.UnlockProof memory proof2 = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId2,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256(abi.encode(stateB, "new")),
                nullifier: nullifier, // REUSE
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        stateLocks.unlock(proof2);
    }

    // =========================================================================
    // 4. EXPIRED LOCK ATTACKS
    // =========================================================================

    /// @notice Test that expired locks cannot be unlocked
    function test_attack_expiredLockUnlock() public {
        mockVerifier.setVerificationResult(true);

        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 lockId = stateLocks.createLock(
            keccak256("state_expire"),
            keccak256("predicate_expire"),
            keccak256("policy_expire"),
            testDomain,
            deadline
        );

        // Fast forward past expiry
        vm.warp(block.timestamp + 2 hours);

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state_expire"),
                nullifier: keccak256("null_expire"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // LockExpired error includes the stored deadline, not the current time
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockExpired.selector,
                lockId,
                deadline
            )
        );
        stateLocks.unlock(proof);
    }

    // =========================================================================
    // 5. STATE COMMITMENT MANIPULATION
    // =========================================================================

    /// @notice Test that Merkle root validation catches stale roots
    function test_attack_staleMerkleRoot() public {
        bytes32 nullifier = keccak256("merkle_test_null");
        bytes32 commitment = keccak256("merkle_test_commit");

        // Register and get current root
        nullifierRegistry.registerNullifier(nullifier, commitment);

        // Fabricate a fake root
        bytes32 fakeRoot = keccak256("fabricated_root");
        assertFalse(
            nullifierRegistry.isValidRoot(fakeRoot),
            "Fabricated root must not be valid"
        );
    }

    /// @notice Test Merkle proof verification rejects invalid proofs
    function test_attack_fakeMerkleProof() public {
        bytes32 nullifier = keccak256("merkle_proof_null");
        bytes32 commitment = keccak256("merkle_proof_commit");

        nullifierRegistry.registerNullifier(nullifier, commitment);

        // Get the current root
        (, bytes32 currentRoot, ) = nullifierRegistry.getTreeStats();

        // Construct a fake proof (must match TREE_DEPTH = 20)
        bytes32[] memory fakeProof = new bytes32[](20);
        for (uint256 i = 0; i < 20; i++) {
            fakeProof[i] = keccak256(abi.encodePacked("fake_node", i));
        }

        // The fake proof should not verify
        bool valid = nullifierRegistry.verifyMerkleProof(
            nullifier,
            0, // wrong index
            fakeProof,
            currentRoot
        );
        assertFalse(valid, "Fake Merkle proof must not verify");
    }

    // =========================================================================
    // 6. HASH COLLISION ATTEMPTS ON NULLIFIER DERIVATION
    // =========================================================================

    /// @notice Test that different inputs produce different nullifiers (collision resistance)
    function testFuzz_attack_hashCollisionResistance(
        bytes32 input1,
        bytes32 input2
    ) public pure {
        vm.assume(input1 != input2);

        bytes32 nullifier1 = keccak256(
            abi.encodePacked("soul_nullifier_v3", input1)
        );
        bytes32 nullifier2 = keccak256(
            abi.encodePacked("soul_nullifier_v3", input2)
        );

        assertNotEq(
            nullifier1,
            nullifier2,
            "Different inputs must produce different nullifiers"
        );
    }

    /// @notice Test that domain separation prevents cross-domain collisions
    function test_attack_crossDomainNullifierIsolation() public {
        bytes32 baseSecret = keccak256("shared_secret");

        bytes32 nullifierDomain1 = keccak256(
            abi.encodePacked("soul_domain_1", baseSecret)
        );
        bytes32 nullifierDomain2 = keccak256(
            abi.encodePacked("soul_domain_2", baseSecret)
        );

        assertNotEq(
            nullifierDomain1,
            nullifierDomain2,
            "Same secret must produce different nullifiers across domains"
        );

        // Both can be registered without conflict
        nullifierRegistry.registerNullifier(
            nullifierDomain1,
            keccak256("commit1")
        );
        nullifierRegistry.registerNullifier(
            nullifierDomain2,
            keccak256("commit2")
        );
    }

    // =========================================================================
    // 7. BN254 SCALAR FIELD BOUNDARY TESTS
    // =========================================================================

    /// @notice Test that scalars at field boundary edges are handled correctly
    function test_attack_scalarFieldBoundary() public pure {
        // Zero scalar
        bytes32 zeroHash = keccak256(abi.encodePacked(uint256(0)));
        assertTrue(zeroHash != bytes32(0), "Hash of zero should be non-zero");

        // Scalar at FR_MODULUS - 1 (last valid scalar)
        bytes32 maxHash = keccak256(abi.encodePacked(FR_MODULUS - 1));
        assertTrue(
            maxHash != bytes32(0),
            "Hash of max scalar should be non-zero"
        );

        // Scalar at FR_MODULUS (wraps to 0 in Noir, but in EVM it's just a big uint)
        bytes32 overflowHash = keccak256(abi.encodePacked(FR_MODULUS));
        bytes32 zeroScalarHash = keccak256(abi.encodePacked(uint256(0)));
        assertNotEq(
            overflowHash,
            zeroScalarHash,
            "Overflow scalar must not collide with zero"
        );
    }

    /// @notice Fuzz: all nullifiers derived from field elements are unique
    function testFuzz_attack_fieldElementNullifierUniqueness(
        uint256 scalar1,
        uint256 scalar2
    ) public pure {
        scalar1 = bound(scalar1, 0, FR_MODULUS - 1);
        scalar2 = bound(scalar2, 0, FR_MODULUS - 1);
        vm.assume(scalar1 != scalar2);

        bytes32 null1 = keccak256(abi.encodePacked("soul_null", scalar1));
        bytes32 null2 = keccak256(abi.encodePacked("soul_null", scalar2));

        assertNotEq(
            null1,
            null2,
            "Different field elements must produce different nullifiers"
        );
    }

    // =========================================================================
    // 8. LOCK DOMAIN ISOLATION
    // =========================================================================

    /// @notice Test that locks with invalid domain separator are rejected
    function test_attack_invalidDomainSeparator() public {
        bytes32 unregisteredDomain = keccak256("UNREGISTERED_DOMAIN");

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InvalidDomainSeparator.selector,
                unregisteredDomain
            )
        );
        stateLocks.createLock(
            keccak256("state"),
            keccak256("predicate"),
            keccak256("policy"),
            unregisteredDomain,
            uint64(block.timestamp + 1 days)
        );
    }

    /// @notice Test that lock IDs are deterministically unique
    function testFuzz_attack_lockIdUniqueness(
        bytes32 state1,
        bytes32 state2
    ) public {
        vm.assume(state1 != bytes32(0) && state2 != bytes32(0));
        vm.assume(state1 != state2);

        bytes32 lockId1 = stateLocks.createLock(
            state1,
            keccak256("pred"),
            keccak256("pol"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        bytes32 lockId2 = stateLocks.createLock(
            state2,
            keccak256("pred"),
            keccak256("pol"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        assertNotEq(
            lockId1,
            lockId2,
            "Different states must produce different lock IDs"
        );
    }

    // =========================================================================
    // 9. ALREADY-UNLOCKED LOCK ATTACK
    // =========================================================================

    /// @notice Test that unlocking an already-unlocked lock reverts
    function test_attack_doubleUnlock() public {
        mockVerifier.setVerificationResult(true);

        bytes32 lockId = stateLocks.createLock(
            keccak256("state_double"),
            keccak256("predicate_double"),
            keccak256("policy_double"),
            testDomain,
            uint64(block.timestamp + 1 days)
        );

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(1))),
                newStateCommitment: keccak256("new_state_double"),
                nullifier: keccak256("null_double"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        // First unlock should succeed
        stateLocks.unlock(proof);

        // Second unlock with different nullifier should fail (lock already unlocked)
        ZKBoundStateLocks.UnlockProof memory replayProof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: abi.encodePacked(bytes32(uint256(2))),
                newStateCommitment: keccak256("different_state"),
                nullifier: keccak256("different_null"),
                verifierKeyHash: MOCK_VK_HASH,
                auxiliaryData: ""
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockAlreadyUnlocked.selector,
                lockId
            )
        );
        stateLocks.unlock(replayProof);
    }
}
